rule TTP_XOR_MULT_DOSStub_d8e0 {
  strings:
    $key_d8e0 = { 8c 88 [2] f8 90 [2] bf 92 [2] f8 83 [2] b6 8f [2] ba 85 [2] ad 8e [2] b6 c0 [2] 8b }

  condition:
    any of them
}