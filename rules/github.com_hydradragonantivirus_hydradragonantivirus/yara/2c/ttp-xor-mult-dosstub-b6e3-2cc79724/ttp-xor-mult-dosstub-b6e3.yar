rule TTP_XOR_MULT_DOSStub_b6e3 {
  strings:
    $key_b6e3 = { e2 8b [2] 96 93 [2] d1 91 [2] 96 80 [2] d8 8c [2] d4 86 [2] c3 8d [2] d8 c3 [2] e5 }

  condition:
    any of them
}