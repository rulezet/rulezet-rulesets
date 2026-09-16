rule TTP_XOR_MULT_DOSStub_e026 {
  strings:
    $key_e026 = { b4 4e [2] c0 56 [2] 87 54 [2] c0 45 [2] 8e 49 [2] 82 43 [2] 95 48 [2] 8e 06 [2] b3 }

  condition:
    any of them
}