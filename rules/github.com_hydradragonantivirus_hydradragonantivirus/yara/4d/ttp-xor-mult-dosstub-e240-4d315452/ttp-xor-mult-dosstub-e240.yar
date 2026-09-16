rule TTP_XOR_MULT_DOSStub_e240 {
  strings:
    $key_e240 = { b6 28 [2] c2 30 [2] 85 32 [2] c2 23 [2] 8c 2f [2] 80 25 [2] 97 2e [2] 8c 60 [2] b1 }

  condition:
    any of them
}