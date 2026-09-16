rule TTP_XOR_MULT_DOSStub_e07f {
  strings:
    $key_e07f = { b4 17 [2] c0 0f [2] 87 0d [2] c0 1c [2] 8e 10 [2] 82 1a [2] 95 11 [2] 8e 5f [2] b3 }

  condition:
    any of them
}