rule TTP_XOR_MULT_DOSStub_509f {
  strings:
    $key_509f = { 04 f7 [2] 70 ef [2] 37 ed [2] 70 fc [2] 3e f0 [2] 32 fa [2] 25 f1 [2] 3e bf [2] 03 }

  condition:
    any of them
}