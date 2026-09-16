rule TTP_XOR_MULT_DOSStub_e256 {
  strings:
    $key_e256 = { b6 3e [2] c2 26 [2] 85 24 [2] c2 35 [2] 8c 39 [2] 80 33 [2] 97 38 [2] 8c 76 [2] b1 }

  condition:
    any of them
}