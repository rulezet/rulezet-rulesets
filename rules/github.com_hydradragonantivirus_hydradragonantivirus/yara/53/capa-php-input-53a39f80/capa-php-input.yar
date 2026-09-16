rule capa_php_input: WEBSHELL PROD {
  meta:
    description = "PHP user input methods, in plain text"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $inp1  = "php://input" wide ascii
    $inp2  = /_GET\s?\[/ wide ascii
        $inp3  = /\(\s?\$_GET\s?\)/ wide ascii
    $inp4  = /_POST\s?\[/ wide ascii
    $inp5  = /\(\s?\$_POST\s?\)/ wide ascii
    $inp6  = /_REQUEST\s?\[/ wide ascii
    $inp7  = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp15 = "_SERVER['HTTP_" wide ascii
    $inp16 = "_SERVER[\"HTTP_" wide ascii
    $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
    $inp18 = "array_values($_SERVER)" wide ascii
    $inp19 = /file_get_contents\("https?:\/\// wide ascii

  condition:
    any of ($inp*)
}