rule TTP_XOR_MULT_DOSStub_929f {
  strings:
    $key_929f = { c6 f7 [2] b2 ef [2] f5 ed [2] b2 fc [2] fc f0 [2] f0 fa [2] e7 f1 [2] fc bf [2] c1 }

  condition:
    any of them
}