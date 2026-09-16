rule TTP_XOR_MULT_DOSStub_07a3 {
  strings:
    $key_07a3 = { 53 cb [2] 27 d3 [2] 60 d1 [2] 27 c0 [2] 69 cc [2] 65 c6 [2] 72 cd [2] 69 83 [2] 54 }

  condition:
    any of them
}