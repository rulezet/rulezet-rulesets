rule TTP_XOR_MULT_DOSStub_e5e2 {
  strings:
    $key_e5e2 = { b1 8a [2] c5 92 [2] 82 90 [2] c5 81 [2] 8b 8d [2] 87 87 [2] 90 8c [2] 8b c2 [2] b6 }

  condition:
    any of them
}