rule TTP_XOR_MULT_DOSStub_16a3 {
  strings:
    $key_16a3 = { 42 cb [2] 36 d3 [2] 71 d1 [2] 36 c0 [2] 78 cc [2] 74 c6 [2] 63 cd [2] 78 83 [2] 45 }

  condition:
    any of them
}