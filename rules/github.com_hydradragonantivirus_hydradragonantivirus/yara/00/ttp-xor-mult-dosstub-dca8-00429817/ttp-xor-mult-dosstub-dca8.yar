rule TTP_XOR_MULT_DOSStub_dca8 {
  strings:
    $key_dca8 = { 88 c0 [2] fc d8 [2] bb da [2] fc cb [2] b2 c7 [2] be cd [2] a9 c6 [2] b2 88 [2] 8f }

  condition:
    any of them
}