rule TTP_XOR_MULT_DOSStub_979f {
  strings:
    $key_979f = { c3 f7 [2] b7 ef [2] f0 ed [2] b7 fc [2] f9 f0 [2] f5 fa [2] e2 f1 [2] f9 bf [2] c4 }

  condition:
    any of them
}