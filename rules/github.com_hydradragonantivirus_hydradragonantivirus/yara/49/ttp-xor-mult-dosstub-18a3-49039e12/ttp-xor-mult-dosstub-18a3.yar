rule TTP_XOR_MULT_DOSStub_18a3 {
  strings:
    $key_18a3 = { 4c cb [2] 38 d3 [2] 7f d1 [2] 38 c0 [2] 76 cc [2] 7a c6 [2] 6d cd [2] 76 83 [2] 4b }

  condition:
    any of them
}