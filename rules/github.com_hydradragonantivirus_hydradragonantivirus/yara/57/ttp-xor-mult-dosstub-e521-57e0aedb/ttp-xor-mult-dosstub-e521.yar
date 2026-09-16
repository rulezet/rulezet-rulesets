rule TTP_XOR_MULT_DOSStub_e521 {
  strings:
    $key_e521 = { b1 49 [2] c5 51 [2] 82 53 [2] c5 42 [2] 8b 4e [2] 87 44 [2] 90 4f [2] 8b 01 [2] b6 }

  condition:
    any of them
}