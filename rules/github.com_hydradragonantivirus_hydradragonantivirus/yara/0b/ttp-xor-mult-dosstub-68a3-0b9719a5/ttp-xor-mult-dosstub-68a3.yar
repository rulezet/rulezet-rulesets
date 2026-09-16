rule TTP_XOR_MULT_DOSStub_68a3 {
  strings:
    $key_68a3 = { 3c cb [2] 48 d3 [2] 0f d1 [2] 48 c0 [2] 06 cc [2] 0a c6 [2] 1d cd [2] 06 83 [2] 3b }

  condition:
    any of them
}