rule TTP_XOR_MULT_DOSStub_669f {
  strings:
    $key_669f = { 32 f7 [2] 46 ef [2] 01 ed [2] 46 fc [2] 08 f0 [2] 04 fa [2] 13 f1 [2] 08 bf [2] 35 }

  condition:
    any of them
}