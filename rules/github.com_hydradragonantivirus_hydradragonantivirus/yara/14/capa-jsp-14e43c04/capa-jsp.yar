rule capa_jsp: WEBSHELL PROD {
  meta:
    description = "capa JSP tag"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/24"

  strings:
    $cjsp1 = "<%" ascii wide
    $cjsp2 = "<jsp:" ascii wide
    $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        $cjsp4 = "/jstl/core" ascii wide

  condition:
    any of ($cjsp*)
}