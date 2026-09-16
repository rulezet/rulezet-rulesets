rule TTP_XOR_MULT_DOSStub_b5a3 {
  strings:
    $key_b5a3 = { e1 cb [2] 95 d3 [2] d2 d1 [2] 95 c0 [2] db cc [2] d7 c6 [2] c0 cd [2] db 83 [2] e6 }

  condition:
    any of them
}