rule TTP_XOR_MULT_DOSStub_2fb6 {
  strings:
    $key_2fb6 = { 7b de [2] 0f c6 [2] 48 c4 [2] 0f d5 [2] 41 d9 [2] 4d d3 [2] 5a d8 [2] 41 96 [2] 7c }

  condition:
    any of them
}