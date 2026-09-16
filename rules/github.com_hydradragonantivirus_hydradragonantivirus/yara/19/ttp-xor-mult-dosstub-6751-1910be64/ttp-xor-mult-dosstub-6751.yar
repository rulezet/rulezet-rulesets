rule TTP_XOR_MULT_DOSStub_6751 {
  strings:
    $key_6751 = { 33 39 [2] 47 21 [2] 00 23 [2] 47 32 [2] 09 3e [2] 05 34 [2] 12 3f [2] 09 71 [2] 34 }

  condition:
    any of them
}