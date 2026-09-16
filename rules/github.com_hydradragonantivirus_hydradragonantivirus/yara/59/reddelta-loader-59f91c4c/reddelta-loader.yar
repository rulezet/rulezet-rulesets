rule RedDelta_loader {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $str1 = "DotNetLoader"
    $str2 = "clipboardinject"
    $str3 = "InjectShellCode"
    $str4 = "WMIBackdoor"

  condition:
    3 of them
}