rule TTP_XOR_MULT_DOSStub_b67f {
  strings:
    $key_b67f = { e2 17 [2] 96 0f [2] d1 0d [2] 96 1c [2] d8 10 [2] d4 1a [2] c3 11 [2] d8 5f [2] e5 }

  condition:
    any of them
}