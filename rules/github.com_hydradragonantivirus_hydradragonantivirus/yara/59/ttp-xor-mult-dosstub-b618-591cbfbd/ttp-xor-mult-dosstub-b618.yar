rule TTP_XOR_MULT_DOSStub_b618 {
  strings:
    $key_b618 = { e2 70 [2] 96 68 [2] d1 6a [2] 96 7b [2] d8 77 [2] d4 7d [2] c3 76 [2] d8 38 [2] e5 }

  condition:
    any of them
}