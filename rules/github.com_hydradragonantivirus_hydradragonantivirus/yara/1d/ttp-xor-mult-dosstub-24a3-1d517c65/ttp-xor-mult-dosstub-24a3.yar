rule TTP_XOR_MULT_DOSStub_24a3 {
  strings:
    $key_24a3 = { 70 cb [2] 04 d3 [2] 43 d1 [2] 04 c0 [2] 4a cc [2] 46 c6 [2] 51 cd [2] 4a 83 [2] 77 }

  condition:
    any of them
}