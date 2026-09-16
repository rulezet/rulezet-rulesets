rule capa_asp_payload: WEBSHELL PROD {
  meta:
    description = "ASP eval versions to dynamically execute code"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/02/06"

  strings:
    $asp_payload0             = "eval_r" fullword nocase wide ascii
    $asp_payload1             = /\beval\s/ nocase wide ascii
    $asp_payload2             = /\beval\(/ nocase wide ascii
    $asp_payload3             = /\beval\"\"/ nocase wide ascii
        $asp_payload4             = /:\s{0,10}eval\b/ nocase wide ascii
    $asp_payload8             = /\bexecute\s?\(/ nocase wide ascii
    $asp_payload9             = /\bexecute\s[\w"]/ nocase wide ascii
    $asp_payload11            = "WSCRIPT.SHELL" fullword nocase wide ascii
    $asp_payload13            = "ExecuteGlobal" fullword nocase wide ascii
    $asp_payload14            = "ExecuteStatement" fullword nocase wide ascii
    $asp_payload15            = "ExecuteStatement" fullword nocase wide ascii
    $asp_multi_payload_one1   = "CreateObject" nocase fullword wide ascii
    $asp_multi_payload_one2   = "addcode" fullword wide ascii
    $asp_multi_payload_one3   = /\.run\b/ wide ascii
    $asp_multi_payload_two1   = "CreateInstanceFromVirtualPath" fullword wide ascii
    $asp_multi_payload_two2   = "ProcessRequest" fullword wide ascii
    $asp_multi_payload_two3   = "BuildManager" fullword wide ascii
    $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
    $asp_multi_payload_three2 = "Process" fullword wide ascii
    $asp_multi_payload_three3 = ".Start" wide ascii
        $asp_multi_payload_four1  = "CreateObject" fullword nocase wide ascii
    $asp_multi_payload_four2  = "TransformNode" fullword nocase wide ascii
    $asp_multi_payload_four3  = "loadxml" fullword nocase wide ascii

        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
    $asp_multi_payload_five2 = ".Start" nocase wide ascii
    $asp_multi_payload_five3 = ".Filename" nocase wide ascii
    $asp_multi_payload_five4 = ".Arguments" nocase wide ascii

  condition:
    any of ($asp_payload*) or
    all of ($asp_multi_payload_one*) or
    all of ($asp_multi_payload_two*) or
    all of ($asp_multi_payload_three*) or
    all of ($asp_multi_payload_four*) or
    all of ($asp_multi_payload_five*)
}