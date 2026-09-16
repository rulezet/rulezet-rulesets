rule TTP_XOR_MULT_DOSStub_6815 {
  strings:
    $key_6815 = { 3c 7d [2] 48 65 [2] 0f 67 [2] 48 76 [2] 06 7a [2] 0a 70 [2] 1d 7b [2] 06 35 [2] 3b }

  condition:
    any of them
}