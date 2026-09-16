rule TTP_XOR_MULT_DOSStub_6877 {
  strings:
    $key_6877 = { 3c 1f [2] 48 07 [2] 0f 05 [2] 48 14 [2] 06 18 [2] 0a 12 [2] 1d 19 [2] 06 57 [2] 3b }

  condition:
    any of them
}