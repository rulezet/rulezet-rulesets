rule TTP_XOR_MULT_DOSStub_61a3 {
  strings:
    $key_61a3 = { 35 cb [2] 41 d3 [2] 06 d1 [2] 41 c0 [2] 0f cc [2] 03 c6 [2] 14 cd [2] 0f 83 [2] 32 }

  condition:
    any of them
}