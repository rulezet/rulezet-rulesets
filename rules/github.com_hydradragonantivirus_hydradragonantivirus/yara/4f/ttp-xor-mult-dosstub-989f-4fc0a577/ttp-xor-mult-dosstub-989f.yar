rule TTP_XOR_MULT_DOSStub_989f {
  strings:
    $key_989f = { cc f7 [2] b8 ef [2] ff ed [2] b8 fc [2] f6 f0 [2] fa fa [2] ed f1 [2] f6 bf [2] cb }

  condition:
    any of them
}