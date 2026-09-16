rule TTP_XOR_MULT_DOSStub_769f {
  strings:
    $key_769f = { 22 f7 [2] 56 ef [2] 11 ed [2] 56 fc [2] 18 f0 [2] 14 fa [2] 03 f1 [2] 18 bf [2] 25 }

  condition:
    any of them
}