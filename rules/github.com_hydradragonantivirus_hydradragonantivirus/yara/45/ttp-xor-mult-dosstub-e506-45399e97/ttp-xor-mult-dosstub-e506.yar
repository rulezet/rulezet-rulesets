rule TTP_XOR_MULT_DOSStub_e506 {
  strings:
    $key_e506 = { b1 6e [2] c5 76 [2] 82 74 [2] c5 65 [2] 8b 69 [2] 87 63 [2] 90 68 [2] 8b 26 [2] b6 }

  condition:
    any of them
}