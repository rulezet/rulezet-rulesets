rule TTP_XOR_MULT_DOSStub_b69c {
  strings:
    $key_b69c = { e2 f4 [2] 96 ec [2] d1 ee [2] 96 ff [2] d8 f3 [2] d4 f9 [2] c3 f2 [2] d8 bc [2] e5 }

  condition:
    any of them
}