rule TTP_XOR_MULT_DOSStub_e041 {
  strings:
    $key_e041 = { b4 29 [2] c0 31 [2] 87 33 [2] c0 22 [2] 8e 2e [2] 82 24 [2] 95 2f [2] 8e 61 [2] b3 }

  condition:
    any of them
}