rule TTP_XOR_MULT_DOSStub_329f {
  strings:
    $key_329f = { 66 f7 [2] 12 ef [2] 55 ed [2] 12 fc [2] 5c f0 [2] 50 fa [2] 47 f1 [2] 5c bf [2] 61 }

  condition:
    any of them
}