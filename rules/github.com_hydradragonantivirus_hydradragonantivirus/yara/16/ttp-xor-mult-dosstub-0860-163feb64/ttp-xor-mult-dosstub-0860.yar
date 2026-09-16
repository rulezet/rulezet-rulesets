rule TTP_XOR_MULT_DOSStub_0860 {
  strings:
    $key_0860 = { 5c 08 [2] 28 10 [2] 6f 12 [2] 28 03 [2] 66 0f [2] 6a 05 [2] 7d 0e [2] 66 40 [2] 5b }

  condition:
    any of them
}