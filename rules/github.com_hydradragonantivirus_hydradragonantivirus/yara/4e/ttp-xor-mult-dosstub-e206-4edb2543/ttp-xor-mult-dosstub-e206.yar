rule TTP_XOR_MULT_DOSStub_e206 {
  strings:
    $key_e206 = { b6 6e [2] c2 76 [2] 85 74 [2] c2 65 [2] 8c 69 [2] 80 63 [2] 97 68 [2] 8c 26 [2] b1 }

  condition:
    any of them
}