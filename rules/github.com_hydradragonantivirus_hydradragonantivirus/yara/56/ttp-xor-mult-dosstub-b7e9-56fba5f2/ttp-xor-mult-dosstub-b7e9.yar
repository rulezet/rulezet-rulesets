rule TTP_XOR_MULT_DOSStub_b7e9 {
  strings:
    $key_b7e9 = { e3 81 [2] 97 99 [2] d0 9b [2] 97 8a [2] d9 86 [2] d5 8c [2] c2 87 [2] d9 c9 [2] e4 }

  condition:
    any of them
}