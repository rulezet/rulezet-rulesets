rule TTP_XOR_MULT_DOSStub_6825 {
  strings:
    $key_6825 = { 3c 4d [2] 48 55 [2] 0f 57 [2] 48 46 [2] 06 4a [2] 0a 40 [2] 1d 4b [2] 06 05 [2] 3b }

  condition:
    any of them
}