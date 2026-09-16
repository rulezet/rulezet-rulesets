rule TTP_XOR_MULT_DOSStub_d09f {
  strings:
    $key_d09f = { 84 f7 [2] f0 ef [2] b7 ed [2] f0 fc [2] be f0 [2] b2 fa [2] a5 f1 [2] be bf [2] 83 }

  condition:
    any of them
}