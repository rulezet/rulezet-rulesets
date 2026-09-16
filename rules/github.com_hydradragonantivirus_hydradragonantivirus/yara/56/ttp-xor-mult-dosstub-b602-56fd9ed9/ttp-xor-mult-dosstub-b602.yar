rule TTP_XOR_MULT_DOSStub_b602 {
  strings:
    $key_b602 = { e2 6a [2] 96 72 [2] d1 70 [2] 96 61 [2] d8 6d [2] d4 67 [2] c3 6c [2] d8 22 [2] e5 }

  condition:
    any of them
}