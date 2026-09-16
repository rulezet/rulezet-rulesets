rule TTP_XOR_MULT_DOSStub_209f {
  strings:
    $key_209f = { 74 f7 [2] 00 ef [2] 47 ed [2] 00 fc [2] 4e f0 [2] 42 fa [2] 55 f1 [2] 4e bf [2] 73 }

  condition:
    any of them
}