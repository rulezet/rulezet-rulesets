rule TTP_XOR_MULT_DOSStub_569f {
  strings:
    $key_569f = { 02 f7 [2] 76 ef [2] 31 ed [2] 76 fc [2] 38 f0 [2] 34 fa [2] 23 f1 [2] 38 bf [2] 05 }

  condition:
    any of them
}