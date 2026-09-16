rule TTP_XOR_MULT_DOSStub_b61f {
  strings:
    $key_b61f = { e2 77 [2] 96 6f [2] d1 6d [2] 96 7c [2] d8 70 [2] d4 7a [2] c3 71 [2] d8 3f [2] e5 }

  condition:
    any of them
}