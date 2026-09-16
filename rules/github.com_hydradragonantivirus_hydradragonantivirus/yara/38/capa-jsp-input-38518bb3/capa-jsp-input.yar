rule capa_jsp_input: WEBSHELL PROD {
  meta:
    description = "capa JSP input"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/24"

  strings:
        $input1 = "getParameter" fullword ascii wide
        $input2 = "getHeaders" fullword ascii wide
    $input3 = "getInputStream" fullword ascii wide
    $input4 = "getReader" fullword ascii wide
    $req1   = "request" fullword ascii wide
    $req2   = "HttpServletRequest" fullword ascii wide
    $req3   = "getRequest" fullword ascii wide

  condition:
    any of ($input*) and
    any of ($req*)
}