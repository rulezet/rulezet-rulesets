rule TTP_XOR_MULT_DOSStub_6829 {
  strings:
    $key_6829 = { 3c 41 [2] 48 59 [2] 0f 5b [2] 48 4a [2] 06 46 [2] 0a 4c [2] 1d 47 [2] 06 09 [2] 3b }

  condition:
    any of them
}