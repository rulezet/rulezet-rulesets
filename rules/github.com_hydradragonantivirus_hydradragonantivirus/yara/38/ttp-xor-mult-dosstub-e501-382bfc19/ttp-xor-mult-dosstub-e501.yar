rule TTP_XOR_MULT_DOSStub_e501 {
  strings:
    $key_e501 = { b1 69 [2] c5 71 [2] 82 73 [2] c5 62 [2] 8b 6e [2] 87 64 [2] 90 6f [2] 8b 21 [2] b6 }

  condition:
    any of them
}