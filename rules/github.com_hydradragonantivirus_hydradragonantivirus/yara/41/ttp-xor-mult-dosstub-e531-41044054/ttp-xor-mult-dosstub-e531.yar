rule TTP_XOR_MULT_DOSStub_e531 {
  strings:
    $key_e531 = { b1 59 [2] c5 41 [2] 82 43 [2] c5 52 [2] 8b 5e [2] 87 54 [2] 90 5f [2] 8b 11 [2] b6 }

  condition:
    any of them
}