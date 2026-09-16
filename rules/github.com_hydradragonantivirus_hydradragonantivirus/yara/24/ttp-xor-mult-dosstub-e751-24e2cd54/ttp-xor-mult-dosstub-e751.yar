rule TTP_XOR_MULT_DOSStub_e751 {
  strings:
    $key_e751 = { b3 39 [2] c7 21 [2] 80 23 [2] c7 32 [2] 89 3e [2] 85 34 [2] 92 3f [2] 89 71 [2] b4 }

  condition:
    any of them
}