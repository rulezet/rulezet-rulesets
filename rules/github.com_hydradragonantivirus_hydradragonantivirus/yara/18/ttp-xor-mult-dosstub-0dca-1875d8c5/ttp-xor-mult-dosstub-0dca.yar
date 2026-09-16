rule TTP_XOR_MULT_DOSStub_0dca {
  strings:
    $key_0dca = { 59 a2 [2] 2d ba [2] 6a b8 [2] 2d a9 [2] 63 a5 [2] 6f af [2] 78 a4 [2] 63 ea [2] 5e }

  condition:
    any of them
}