rule TTP_XOR_MULT_DOSStub_e02a {
  strings:
    $key_e02a = { b4 42 [2] c0 5a [2] 87 58 [2] c0 49 [2] 8e 45 [2] 82 4f [2] 95 44 [2] 8e 0a [2] b3 }

  condition:
    any of them
}