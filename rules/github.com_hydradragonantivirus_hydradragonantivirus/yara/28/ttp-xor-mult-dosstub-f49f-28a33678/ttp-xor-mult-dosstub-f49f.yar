rule TTP_XOR_MULT_DOSStub_f49f {
  strings:
    $key_f49f = { a0 f7 [2] d4 ef [2] 93 ed [2] d4 fc [2] 9a f0 [2] 96 fa [2] 81 f1 [2] 9a bf [2] a7 }

  condition:
    any of them
}