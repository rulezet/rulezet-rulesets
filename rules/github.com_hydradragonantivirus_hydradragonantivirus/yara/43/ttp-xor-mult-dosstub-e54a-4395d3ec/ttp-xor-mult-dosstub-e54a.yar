rule TTP_XOR_MULT_DOSStub_e54a {
  strings:
    $key_e54a = { b1 22 [2] c5 3a [2] 82 38 [2] c5 29 [2] 8b 25 [2] 87 2f [2] 90 24 [2] 8b 6a [2] b6 }

  condition:
    any of them
}