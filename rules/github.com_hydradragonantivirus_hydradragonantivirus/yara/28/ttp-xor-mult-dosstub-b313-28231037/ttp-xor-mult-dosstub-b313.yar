rule TTP_XOR_MULT_DOSStub_b313 {
  strings:
    $key_b313 = { e7 7b [2] 93 63 [2] d4 61 [2] 93 70 [2] dd 7c [2] d1 76 [2] c6 7d [2] dd 33 [2] e0 }

  condition:
    any of them
}