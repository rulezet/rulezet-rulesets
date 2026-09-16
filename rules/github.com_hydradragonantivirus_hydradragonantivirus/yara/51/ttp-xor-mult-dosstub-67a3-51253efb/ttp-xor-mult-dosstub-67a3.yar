rule TTP_XOR_MULT_DOSStub_67a3 {
  strings:
    $key_67a3 = { 33 cb [2] 47 d3 [2] 00 d1 [2] 47 c0 [2] 09 cc [2] 05 c6 [2] 12 cd [2] 09 83 [2] 34 }

  condition:
    any of them
}