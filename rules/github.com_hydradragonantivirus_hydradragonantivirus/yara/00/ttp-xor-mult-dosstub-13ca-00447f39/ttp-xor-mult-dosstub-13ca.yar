rule TTP_XOR_MULT_DOSStub_13ca {
  strings:
    $key_13ca = { 47 a2 [2] 33 ba [2] 74 b8 [2] 33 a9 [2] 7d a5 [2] 71 af [2] 66 a4 [2] 7d ea [2] 40 }

  condition:
    any of them
}