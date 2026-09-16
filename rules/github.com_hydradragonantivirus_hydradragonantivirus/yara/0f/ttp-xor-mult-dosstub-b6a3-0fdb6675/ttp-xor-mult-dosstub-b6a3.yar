rule TTP_XOR_MULT_DOSStub_b6a3 {
  strings:
    $key_b6a3 = { e2 cb [2] 96 d3 [2] d1 d1 [2] 96 c0 [2] d8 cc [2] d4 c6 [2] c3 cd [2] d8 83 [2] e5 }

  condition:
    any of them
}