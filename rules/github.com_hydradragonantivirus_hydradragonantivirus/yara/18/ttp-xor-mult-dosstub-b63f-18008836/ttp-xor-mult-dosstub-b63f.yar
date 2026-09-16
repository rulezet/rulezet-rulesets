rule TTP_XOR_MULT_DOSStub_b63f {
  strings:
    $key_b63f = { e2 57 [2] 96 4f [2] d1 4d [2] 96 5c [2] d8 50 [2] d4 5a [2] c3 51 [2] d8 1f [2] e5 }

  condition:
    any of them
}