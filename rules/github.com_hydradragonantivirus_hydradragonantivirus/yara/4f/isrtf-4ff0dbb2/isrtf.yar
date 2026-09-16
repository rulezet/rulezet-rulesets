rule _isRTF {
  strings:
    $magic_rtf = /^\s*\\\{\\rt/

  condition:
    $magic_rtf and filesize < 25MB
}