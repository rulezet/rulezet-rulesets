rule TTP_XOR_MULT_DOSStub_66a3 {
  strings:
    $key_66a3 = { 32 cb [2] 46 d3 [2] 01 d1 [2] 46 c0 [2] 08 cc [2] 04 c6 [2] 13 cd [2] 08 83 [2] 35 }

  condition:
    any of them
}