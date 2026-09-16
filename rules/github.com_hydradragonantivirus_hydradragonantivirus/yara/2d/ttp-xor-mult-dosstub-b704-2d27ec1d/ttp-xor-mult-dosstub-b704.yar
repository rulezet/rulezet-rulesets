rule TTP_XOR_MULT_DOSStub_b704 {
  strings:
    $key_b704 = { e3 6c [2] 97 74 [2] d0 76 [2] 97 67 [2] d9 6b [2] d5 61 [2] c2 6a [2] d9 24 [2] e4 }

  condition:
    any of them
}