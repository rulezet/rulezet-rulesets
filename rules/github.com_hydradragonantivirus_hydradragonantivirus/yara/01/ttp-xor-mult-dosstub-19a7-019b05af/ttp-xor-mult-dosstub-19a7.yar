rule TTP_XOR_MULT_DOSStub_19a7 {
  strings:
    $key_19a7 = { 4d cf [2] 39 d7 [2] 7e d5 [2] 39 c4 [2] 77 c8 [2] 7b c2 [2] 6c c9 [2] 77 87 [2] 4a }

  condition:
    any of them
}