rule TTP_XOR_MULT_DOSStub_e57f {
  strings:
    $key_e57f = { b1 17 [2] c5 0f [2] 82 0d [2] c5 1c [2] 8b 10 [2] 87 1a [2] 90 11 [2] 8b 5f [2] b6 }

  condition:
    any of them
}