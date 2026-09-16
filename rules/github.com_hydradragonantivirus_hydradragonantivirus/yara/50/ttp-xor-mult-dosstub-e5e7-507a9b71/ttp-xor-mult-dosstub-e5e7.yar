rule TTP_XOR_MULT_DOSStub_e5e7 {
  strings:
    $key_e5e7 = { b1 8f [2] c5 97 [2] 82 95 [2] c5 84 [2] 8b 88 [2] 87 82 [2] 90 89 [2] 8b c7 [2] b6 }

  condition:
    any of them
}