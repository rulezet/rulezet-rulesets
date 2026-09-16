rule TTP_XOR_MULT_DOSStub_b3e3 {
  strings:
    $key_b3e3 = { e7 8b [2] 93 93 [2] d4 91 [2] 93 80 [2] dd 8c [2] d1 86 [2] c6 8d [2] dd c3 [2] e0 }

  condition:
    any of them
}