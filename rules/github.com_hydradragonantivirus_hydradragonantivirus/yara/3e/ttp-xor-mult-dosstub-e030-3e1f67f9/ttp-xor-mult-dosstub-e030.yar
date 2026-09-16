rule TTP_XOR_MULT_DOSStub_e030 {
  strings:
    $key_e030 = { b4 58 [2] c0 40 [2] 87 42 [2] c0 53 [2] 8e 5f [2] 82 55 [2] 95 5e [2] 8e 10 [2] b3 }

  condition:
    any of them
}