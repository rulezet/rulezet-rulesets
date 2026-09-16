rule TTP_XOR_MULT_DOSStub_158d {
  strings:
    $key_158d = { 41 e5 [2] 35 fd [2] 72 ff [2] 35 ee [2] 7b e2 [2] 77 e8 [2] 60 e3 [2] 7b ad [2] 46 }

  condition:
    any of them
}