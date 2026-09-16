rule TTP_XOR_MULT_DOSStub_c3ca {
  strings:
    $key_c3ca = { 97 a2 [2] e3 ba [2] a4 b8 [2] e3 a9 [2] ad a5 [2] a1 af [2] b6 a4 [2] ad ea [2] 90 }

  condition:
    any of them
}