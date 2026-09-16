rule TTP_XOR_MULT_DOSStub_e0f8 {
  strings:
    $key_e0f8 = { b4 90 [2] c0 88 [2] 87 8a [2] c0 9b [2] 8e 97 [2] 82 9d [2] 95 96 [2] 8e d8 [2] b3 }

  condition:
    any of them
}