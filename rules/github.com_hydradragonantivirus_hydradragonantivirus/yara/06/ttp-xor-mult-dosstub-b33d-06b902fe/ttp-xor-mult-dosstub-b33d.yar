rule TTP_XOR_MULT_DOSStub_b33d {
  strings:
    $key_b33d = { e7 55 [2] 93 4d [2] d4 4f [2] 93 5e [2] dd 52 [2] d1 58 [2] c6 53 [2] dd 1d [2] e0 }

  condition:
    any of them
}