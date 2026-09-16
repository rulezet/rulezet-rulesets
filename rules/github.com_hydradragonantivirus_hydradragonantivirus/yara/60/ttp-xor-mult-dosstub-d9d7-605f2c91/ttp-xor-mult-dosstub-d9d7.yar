rule TTP_XOR_MULT_DOSStub_d9d7 {
  strings:
    $key_d9d7 = { 8d bf [2] f9 a7 [2] be a5 [2] f9 b4 [2] b7 b8 [2] bb b2 [2] ac b9 [2] b7 f7 [2] 8a }

  condition:
    any of them
}