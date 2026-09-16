rule TTP_XOR_MULT_DOSStub_b319 {
  strings:
    $key_b319 = { e7 71 [2] 93 69 [2] d4 6b [2] 93 7a [2] dd 76 [2] d1 7c [2] c6 77 [2] dd 39 [2] e0 }

  condition:
    any of them
}