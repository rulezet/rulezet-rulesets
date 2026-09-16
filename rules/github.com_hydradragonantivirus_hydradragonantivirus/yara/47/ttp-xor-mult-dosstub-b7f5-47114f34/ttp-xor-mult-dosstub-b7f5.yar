rule TTP_XOR_MULT_DOSStub_b7f5 {
  strings:
    $key_b7f5 = { e3 9d [2] 97 85 [2] d0 87 [2] 97 96 [2] d9 9a [2] d5 90 [2] c2 9b [2] d9 d5 [2] e4 }

  condition:
    any of them
}