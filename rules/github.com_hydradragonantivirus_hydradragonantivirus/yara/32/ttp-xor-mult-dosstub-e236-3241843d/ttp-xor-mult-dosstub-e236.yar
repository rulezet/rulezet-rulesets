rule TTP_XOR_MULT_DOSStub_e236 {
  strings:
    $key_e236 = { b6 5e [2] c2 46 [2] 85 44 [2] c2 55 [2] 8c 59 [2] 80 53 [2] 97 58 [2] 8c 16 [2] b1 }

  condition:
    any of them
}