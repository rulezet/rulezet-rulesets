rule TTP_XOR_MULT_DOSStub_e0f9 {
  strings:
    $key_e0f9 = { b4 91 [2] c0 89 [2] 87 8b [2] c0 9a [2] 8e 96 [2] 82 9c [2] 95 97 [2] 8e d9 [2] b3 }

  condition:
    any of them
}