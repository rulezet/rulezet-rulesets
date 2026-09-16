rule TTP_XOR_MULT_DOSStub_d59f {
  strings:
    $key_d59f = { 81 f7 [2] f5 ef [2] b2 ed [2] f5 fc [2] bb f0 [2] b7 fa [2] a0 f1 [2] bb bf [2] 86 }

  condition:
    any of them
}