rule TTP_XOR_MULT_DOSStub_e55a {
  strings:
    $key_e55a = { b1 32 [2] c5 2a [2] 82 28 [2] c5 39 [2] 8b 35 [2] 87 3f [2] 90 34 [2] 8b 7a [2] b6 }

  condition:
    any of them
}