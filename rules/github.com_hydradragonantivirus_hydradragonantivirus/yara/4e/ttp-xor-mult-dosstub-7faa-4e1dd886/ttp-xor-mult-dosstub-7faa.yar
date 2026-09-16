rule TTP_XOR_MULT_DOSStub_7faa {
  strings:
    $key_7faa = { 2b c2 [2] 5f da [2] 18 d8 [2] 5f c9 [2] 11 c5 [2] 1d cf [2] 0a c4 [2] 11 8a [2] 2c }

  condition:
    any of them
}