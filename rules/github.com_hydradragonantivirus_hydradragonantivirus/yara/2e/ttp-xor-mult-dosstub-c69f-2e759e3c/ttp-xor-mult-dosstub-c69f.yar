rule TTP_XOR_MULT_DOSStub_c69f {
  strings:
    $key_c69f = { 92 f7 [2] e6 ef [2] a1 ed [2] e6 fc [2] a8 f0 [2] a4 fa [2] b3 f1 [2] a8 bf [2] 95 }

  condition:
    any of them
}