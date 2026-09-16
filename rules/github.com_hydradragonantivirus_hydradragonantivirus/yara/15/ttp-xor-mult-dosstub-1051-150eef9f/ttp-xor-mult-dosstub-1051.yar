rule TTP_XOR_MULT_DOSStub_1051 {
  strings:
    $key_1051 = { 44 39 [2] 30 21 [2] 77 23 [2] 30 32 [2] 7e 3e [2] 72 34 [2] 65 3f [2] 7e 71 [2] 43 }

  condition:
    any of them
}