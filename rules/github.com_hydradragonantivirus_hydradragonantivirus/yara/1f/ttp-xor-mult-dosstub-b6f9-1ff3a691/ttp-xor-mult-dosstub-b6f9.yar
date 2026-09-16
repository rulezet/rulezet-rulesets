rule TTP_XOR_MULT_DOSStub_b6f9 {
  strings:
    $key_b6f9 = { e2 91 [2] 96 89 [2] d1 8b [2] 96 9a [2] d8 96 [2] d4 9c [2] c3 97 [2] d8 d9 [2] e5 }

  condition:
    any of them
}