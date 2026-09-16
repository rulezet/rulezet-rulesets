rule TTP_XOR_MULT_DOSStub_b612 {
  strings:
    $key_b612 = { e2 7a [2] 96 62 [2] d1 60 [2] 96 71 [2] d8 7d [2] d4 77 [2] c3 7c [2] d8 32 [2] e5 }

  condition:
    any of them
}