rule TTP_XOR_MULT_DOSStub_6ea3 {
  strings:
    $key_6ea3 = { 3a cb [2] 4e d3 [2] 09 d1 [2] 4e c0 [2] 00 cc [2] 0c c6 [2] 1b cd [2] 00 83 [2] 3d }

  condition:
    any of them
}