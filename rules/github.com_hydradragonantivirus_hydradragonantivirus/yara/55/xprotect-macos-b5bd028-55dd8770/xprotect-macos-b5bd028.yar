rule XProtect_MACOS_b5bd028 {
  meta:
    description = "MACOS.b5bd028"

  strings:
    $a  = "#!/bin/bash"
    $b1 = "/paramsJson.json"
    $b2 = "/.Resources"

  condition:
    $a at 0 and all of ($b*) and filesize < 1KB
}