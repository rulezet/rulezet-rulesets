rule TTP_XOR_MULT_DOSStub_5ea3 {
  strings:
    $key_5ea3 = { 0a cb [2] 7e d3 [2] 39 d1 [2] 7e c0 [2] 30 cc [2] 3c c6 [2] 2b cd [2] 30 83 [2] 0d }

  condition:
    any of them
}