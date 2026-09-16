rule TTP_XOR_MULT_DOSStub_b30e {
  strings:
    $key_b30e = { e7 66 [2] 93 7e [2] d4 7c [2] 93 6d [2] dd 61 [2] d1 6b [2] c6 60 [2] dd 2e [2] e0 }

  condition:
    any of them
}