rule TTP_XOR_MULT_DOSStub_e047 {
  strings:
    $key_e047 = { b4 2f [2] c0 37 [2] 87 35 [2] c0 24 [2] 8e 28 [2] 82 22 [2] 95 29 [2] 8e 67 [2] b3 }

  condition:
    any of them
}