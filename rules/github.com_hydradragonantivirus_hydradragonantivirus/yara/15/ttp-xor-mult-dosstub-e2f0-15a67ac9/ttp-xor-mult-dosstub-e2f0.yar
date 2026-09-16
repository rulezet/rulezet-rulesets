rule TTP_XOR_MULT_DOSStub_e2f0 {
  strings:
    $key_e2f0 = { b6 98 [2] c2 80 [2] 85 82 [2] c2 93 [2] 8c 9f [2] 80 95 [2] 97 9e [2] 8c d0 [2] b1 }

  condition:
    any of them
}