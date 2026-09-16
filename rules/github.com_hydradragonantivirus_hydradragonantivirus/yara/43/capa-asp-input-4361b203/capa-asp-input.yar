rule capa_asp_input: WEBSHELL PROD {
  meta:
    description = "ASP input"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/03/07"

  strings:
            $asp_input1      = "request" fullword nocase wide ascii
    $asp_input2      = "Page_Load" fullword nocase wide ascii
        $asp_input3      = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
    $asp_xml_http    = "Microsoft.XMLHTTP" fullword nocase wide ascii
    $asp_xml_method1 = "GET" fullword wide ascii
    $asp_xml_method2 = "POST" fullword wide ascii
    $asp_xml_method3 = "HEAD" fullword wide ascii
        $asp_form1       = "<form " wide ascii
    $asp_form2       = "<Form " wide ascii
    $asp_form3       = "<FORM " wide ascii
    $asp_asp         = "<asp:" wide ascii
    $asp_text1       = ".text" wide ascii
    $asp_text2       = ".Text" wide ascii

  condition:
    any of ($asp_input*) or
    (
      $asp_xml_http and
      any of ($asp_xml_method*)
    ) or
    (
      any of ($asp_form*) and
      any of ($asp_text*) and
      $asp_asp
    )
}