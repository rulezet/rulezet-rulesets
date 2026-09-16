rule TTP_XOR_MULT_DOSStub_63ca {
  strings:
    $key_63ca = { 37 a2 [2] 43 ba [2] 04 b8 [2] 43 a9 [2] 0d a5 [2] 01 af [2] 16 a4 [2] 0d ea [2] 30 }

  condition:
    any of them
}