rule TTP_XOR_MULT_DOSStub_3251 {
  strings:
    $key_3251 = { 66 39 [2] 12 21 [2] 55 23 [2] 12 32 [2] 5c 3e [2] 50 34 [2] 47 3f [2] 5c 71 [2] 61 }

  condition:
    any of them
}