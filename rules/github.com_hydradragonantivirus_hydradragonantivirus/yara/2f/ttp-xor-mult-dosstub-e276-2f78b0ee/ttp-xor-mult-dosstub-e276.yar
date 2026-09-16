rule TTP_XOR_MULT_DOSStub_e276 {
  strings:
    $key_e276 = { b6 1e [2] c2 06 [2] 85 04 [2] c2 15 [2] 8c 19 [2] 80 13 [2] 97 18 [2] 8c 56 [2] b1 }

  condition:
    any of them
}