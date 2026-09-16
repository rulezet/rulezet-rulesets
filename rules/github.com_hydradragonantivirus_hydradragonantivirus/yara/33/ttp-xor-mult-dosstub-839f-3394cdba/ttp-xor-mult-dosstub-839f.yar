rule TTP_XOR_MULT_DOSStub_839f {
  strings:
    $key_839f = { d7 f7 [2] a3 ef [2] e4 ed [2] a3 fc [2] ed f0 [2] e1 fa [2] f6 f1 [2] ed bf [2] d0 }

  condition:
    any of them
}