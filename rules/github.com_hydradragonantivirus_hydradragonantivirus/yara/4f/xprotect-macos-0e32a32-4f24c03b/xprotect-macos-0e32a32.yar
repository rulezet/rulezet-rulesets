rule XProtect_MACOS_0e32a32 {
  meta:
    description = "MACOS.0e32a32"

  strings:
    $a = "#!"

    $b1 = { ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b }
    $b2 = "mktemp -d /tmp"
    $b3 = { 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 20 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d }
    $b4 = "nohup /bin/bash -c \"eval"

    $c1 = "'\\.(command)$'"
    $c2 = "U2FsdGVkX1"
    $c3 = "killall Terminal"

  condition:
    filesize < 10KB and $a at 0 and (all of ($b*) or all of ($c*))
}