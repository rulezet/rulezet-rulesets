rule TTP_XOR_MULT_DOSStub_279f {
  strings:
    $key_279f = { 73 f7 [2] 07 ef [2] 40 ed [2] 07 fc [2] 49 f0 [2] 45 fa [2] 52 f1 [2] 49 bf [2] 74 }

  condition:
    any of them
}