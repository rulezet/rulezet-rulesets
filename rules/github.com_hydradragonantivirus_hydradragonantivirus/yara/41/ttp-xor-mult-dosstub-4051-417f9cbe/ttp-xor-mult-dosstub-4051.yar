rule TTP_XOR_MULT_DOSStub_4051 {
  strings:
    $key_4051 = { 14 39 [2] 60 21 [2] 27 23 [2] 60 32 [2] 2e 3e [2] 22 34 [2] 35 3f [2] 2e 71 [2] 13 }

  condition:
    any of them
}