rule capa_jsp_payload: WEBSHELL PROD {
  meta:
    description = "capa JSP payload"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/02/27"

  strings:
    $payload1    = "ProcessBuilder" fullword ascii wide
    $payload2    = "processCmd" fullword ascii wide
        $rt_payload1 = "Runtime" fullword ascii wide
    $rt_payload2 = "getRuntime" fullword ascii wide
    $rt_payload3 = "exec" fullword ascii wide

  condition:
    1 of ($payload*) or
    all of ($rt_payload*)
}