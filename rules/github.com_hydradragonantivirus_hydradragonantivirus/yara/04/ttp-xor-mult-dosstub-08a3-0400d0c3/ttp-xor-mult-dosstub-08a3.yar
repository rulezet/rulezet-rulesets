rule TTP_XOR_MULT_DOSStub_08a3 {
  strings:
    $key_08a3 = { 5c cb [2] 28 d3 [2] 6f d1 [2] 28 c0 [2] 66 cc [2] 6a c6 [2] 7d cd [2] 66 83 [2] 5b }

  condition:
    any of them
}