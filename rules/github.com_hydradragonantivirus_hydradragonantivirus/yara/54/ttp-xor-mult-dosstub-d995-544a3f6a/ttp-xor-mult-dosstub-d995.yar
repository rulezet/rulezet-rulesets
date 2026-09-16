rule TTP_XOR_MULT_DOSStub_d995 {
  strings:
    $key_d995 = { 8d fd [2] f9 e5 [2] be e7 [2] f9 f6 [2] b7 fa [2] bb f0 [2] ac fb [2] b7 b5 [2] 8a }

  condition:
    any of them
}