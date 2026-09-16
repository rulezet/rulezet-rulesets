rule TTP_XOR_MULT_DOSStub_32a3 {
  strings:
    $key_32a3 = { 66 cb [2] 12 d3 [2] 55 d1 [2] 12 c0 [2] 5c cc [2] 50 c6 [2] 47 cd [2] 5c 83 [2] 61 }

  condition:
    any of them
}