rule TTP_XOR_MULT_DOSStub_c9ca {
  strings:
    $key_c9ca = { 9d a2 [2] e9 ba [2] ae b8 [2] e9 a9 [2] a7 a5 [2] ab af [2] bc a4 [2] a7 ea [2] 9a }

  condition:
    any of them
}