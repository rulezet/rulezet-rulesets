rule TTP_XOR_MULT_DOSStub_b60f {
  strings:
    $key_b60f = { e2 67 [2] 96 7f [2] d1 7d [2] 96 6c [2] d8 60 [2] d4 6a [2] c3 61 [2] d8 2f [2] e5 }

  condition:
    any of them
}