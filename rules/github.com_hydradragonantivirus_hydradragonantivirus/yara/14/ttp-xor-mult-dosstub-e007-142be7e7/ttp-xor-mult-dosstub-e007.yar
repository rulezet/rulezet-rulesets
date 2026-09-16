rule TTP_XOR_MULT_DOSStub_e007 {
  strings:
    $key_e007 = { b4 6f [2] c0 77 [2] 87 75 [2] c0 64 [2] 8e 68 [2] 82 62 [2] 95 69 [2] 8e 27 [2] b3 }

  condition:
    any of them
}