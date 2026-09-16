rule TTP_XOR_MULT_DOSStub_e57a {
  strings:
    $key_e57a = { b1 12 [2] c5 0a [2] 82 08 [2] c5 19 [2] 8b 15 [2] 87 1f [2] 90 14 [2] 8b 5a [2] b6 }

  condition:
    any of them
}