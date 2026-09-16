rule TTP_XOR_MULT_DOSStub_6faa {
  strings:
    $key_6faa = { 3b c2 [2] 4f da [2] 08 d8 [2] 4f c9 [2] 01 c5 [2] 0d cf [2] 1a c4 [2] 01 8a [2] 3c }

  condition:
    any of them
}