rule TTP_XOR_MULT_DOSStub_1dca {
  strings:
    $key_1dca = { 49 a2 [2] 3d ba [2] 7a b8 [2] 3d a9 [2] 73 a5 [2] 7f af [2] 68 a4 [2] 73 ea [2] 4e }

  condition:
    any of them
}