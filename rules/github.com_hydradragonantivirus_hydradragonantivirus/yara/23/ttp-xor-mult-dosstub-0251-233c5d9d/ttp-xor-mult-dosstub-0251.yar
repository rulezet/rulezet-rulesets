rule TTP_XOR_MULT_DOSStub_0251 {
  strings:
    $key_0251 = { 56 39 [2] 22 21 [2] 65 23 [2] 22 32 [2] 6c 3e [2] 60 34 [2] 77 3f [2] 6c 71 [2] 51 }

  condition:
    any of them
}