rule TTP_XOR_MULT_DOSStub_26a3 {
  strings:
    $key_26a3 = { 72 cb [2] 06 d3 [2] 41 d1 [2] 06 c0 [2] 48 cc [2] 44 c6 [2] 53 cd [2] 48 83 [2] 75 }

  condition:
    any of them
}