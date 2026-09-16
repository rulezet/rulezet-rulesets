rule TTP_XOR_MULT_DOSStub_3751 {
  strings:
    $key_3751 = { 63 39 [2] 17 21 [2] 50 23 [2] 17 32 [2] 59 3e [2] 55 34 [2] 42 3f [2] 59 71 [2] 64 }

  condition:
    any of them
}