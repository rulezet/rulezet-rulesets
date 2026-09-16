rule TTP_XOR_MULT_DOSStub_e527 {
  strings:
    $key_e527 = { b1 4f [2] c5 57 [2] 82 55 [2] c5 44 [2] 8b 48 [2] 87 42 [2] 90 49 [2] 8b 07 [2] b6 }

  condition:
    any of them
}