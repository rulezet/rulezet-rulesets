rule Win_Trojan_Java_98 {
  strings:
    $a0 = "GetWindowsDirectory"

    $a1 = ".exe"

    $a2 = "URLDownloadToFile"

    $a3 = "Runtime"

    $a4 = "exec"

  condition:
    $a0 and $a1 and $a2 and $a3 and $a4
}