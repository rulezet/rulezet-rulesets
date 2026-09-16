rule TTP_XOR_MULT_DOSStub_e020 {
  strings:
    $key_e020 = { b4 48 [2] c0 50 [2] 87 52 [2] c0 43 [2] 8e 4f [2] 82 45 [2] 95 4e [2] 8e 00 [2] b3 }

  condition:
    any of them
}