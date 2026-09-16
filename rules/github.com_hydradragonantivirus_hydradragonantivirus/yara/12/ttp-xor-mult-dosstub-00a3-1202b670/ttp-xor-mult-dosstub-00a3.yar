rule TTP_XOR_MULT_DOSStub_00a3 {
  strings:
    $key_00a3 = { 54 cb [2] 20 d3 [2] 67 d1 [2] 20 c0 [2] 6e cc [2] 62 c6 [2] 75 cd [2] 6e 83 [2] 53 }

  condition:
    any of them
}