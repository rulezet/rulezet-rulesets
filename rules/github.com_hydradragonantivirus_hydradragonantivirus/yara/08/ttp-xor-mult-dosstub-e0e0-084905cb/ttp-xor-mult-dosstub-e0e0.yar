rule TTP_XOR_MULT_DOSStub_e0e0 {
  strings:
    $key_e0e0 = { b4 88 [2] c0 90 [2] 87 92 [2] c0 83 [2] 8e 8f [2] 82 85 [2] 95 8e [2] 8e c0 [2] b3 }

  condition:
    any of them
}