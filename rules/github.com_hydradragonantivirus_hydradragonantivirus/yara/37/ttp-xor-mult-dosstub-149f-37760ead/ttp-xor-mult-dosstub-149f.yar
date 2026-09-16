rule TTP_XOR_MULT_DOSStub_149f {
  strings:
    $key_149f = { 40 f7 [2] 34 ef [2] 73 ed [2] 34 fc [2] 7a f0 [2] 76 fa [2] 61 f1 [2] 7a bf [2] 47 }

  condition:
    any of them
}