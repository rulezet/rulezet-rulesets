rule TTP_XOR_MULT_DOSStub_d79f {
  strings:
    $key_d79f = { 83 f7 [2] f7 ef [2] b0 ed [2] f7 fc [2] b9 f0 [2] b5 fa [2] a2 f1 [2] b9 bf [2] 84 }

  condition:
    any of them
}