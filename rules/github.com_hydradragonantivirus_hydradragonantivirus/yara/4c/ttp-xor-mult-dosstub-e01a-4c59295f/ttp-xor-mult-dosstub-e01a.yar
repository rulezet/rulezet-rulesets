rule TTP_XOR_MULT_DOSStub_e01a {
  strings:
    $key_e01a = { b4 72 [2] c0 6a [2] 87 68 [2] c0 79 [2] 8e 75 [2] 82 7f [2] 95 74 [2] 8e 3a [2] b3 }

  condition:
    any of them
}