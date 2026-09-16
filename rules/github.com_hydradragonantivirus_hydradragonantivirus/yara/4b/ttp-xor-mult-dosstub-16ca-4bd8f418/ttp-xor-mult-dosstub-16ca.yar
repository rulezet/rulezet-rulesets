rule TTP_XOR_MULT_DOSStub_16ca {
  strings:
    $key_16ca = { 42 a2 [2] 36 ba [2] 71 b8 [2] 36 a9 [2] 78 a5 [2] 74 af [2] 63 a4 [2] 78 ea [2] 45 }

  condition:
    any of them
}