rule TTP_XOR_MULT_DOSStub_4dca {
  strings:
    $key_4dca = { 19 a2 [2] 6d ba [2] 2a b8 [2] 6d a9 [2] 23 a5 [2] 2f af [2] 38 a4 [2] 23 ea [2] 1e }

  condition:
    any of them
}