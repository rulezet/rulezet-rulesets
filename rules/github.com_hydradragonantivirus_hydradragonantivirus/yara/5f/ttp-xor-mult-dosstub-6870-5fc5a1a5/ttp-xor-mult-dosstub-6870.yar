rule TTP_XOR_MULT_DOSStub_6870 {
  strings:
    $key_6870 = { 3c 18 [2] 48 00 [2] 0f 02 [2] 48 13 [2] 06 1f [2] 0a 15 [2] 1d 1e [2] 06 50 [2] 3b }

  condition:
    any of them
}