rule TTP_XOR_MULT_DOSStub_da9f {
  strings:
    $key_da9f = { 8e f7 [2] fa ef [2] bd ed [2] fa fc [2] b4 f0 [2] b8 fa [2] af f1 [2] b4 bf [2] 89 }

  condition:
    any of them
}