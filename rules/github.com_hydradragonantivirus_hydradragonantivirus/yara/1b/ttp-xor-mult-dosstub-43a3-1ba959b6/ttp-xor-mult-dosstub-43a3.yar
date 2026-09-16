rule TTP_XOR_MULT_DOSStub_43a3 {
  strings:
    $key_43a3 = { 17 cb [2] 63 d3 [2] 24 d1 [2] 63 c0 [2] 2d cc [2] 21 c6 [2] 36 cd [2] 2d 83 [2] 10 }

  condition:
    any of them
}