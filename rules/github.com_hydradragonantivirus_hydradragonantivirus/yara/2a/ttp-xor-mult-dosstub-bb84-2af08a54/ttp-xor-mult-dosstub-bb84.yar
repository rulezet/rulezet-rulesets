rule TTP_XOR_MULT_DOSStub_bb84 {
  strings:
    $key_bb84 = { ef ec [2] 9b f4 [2] dc f6 [2] 9b e7 [2] d5 eb [2] d9 e1 [2] ce ea [2] d5 a4 [2] e8 }

  condition:
    any of them
}