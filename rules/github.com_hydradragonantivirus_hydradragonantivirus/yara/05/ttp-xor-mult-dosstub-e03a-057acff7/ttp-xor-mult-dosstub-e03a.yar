rule TTP_XOR_MULT_DOSStub_e03a {
  strings:
    $key_e03a = { b4 52 [2] c0 4a [2] 87 48 [2] c0 59 [2] 8e 55 [2] 82 5f [2] 95 54 [2] 8e 1a [2] b3 }

  condition:
    any of them
}