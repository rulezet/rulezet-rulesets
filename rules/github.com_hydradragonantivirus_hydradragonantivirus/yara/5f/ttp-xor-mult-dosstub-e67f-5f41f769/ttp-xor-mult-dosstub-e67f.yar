rule TTP_XOR_MULT_DOSStub_e67f {
  strings:
    $key_e67f = { b2 17 [2] c6 0f [2] 81 0d [2] c6 1c [2] 88 10 [2] 84 1a [2] 93 11 [2] 88 5f [2] b5 }

  condition:
    any of them
}