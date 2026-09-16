rule TTP_XOR_MULT_DOSStub_a29f {
  strings:
    $key_a29f = { f6 f7 [2] 82 ef [2] c5 ed [2] 82 fc [2] cc f0 [2] c0 fa [2] d7 f1 [2] cc bf [2] f1 }

  condition:
    any of them
}