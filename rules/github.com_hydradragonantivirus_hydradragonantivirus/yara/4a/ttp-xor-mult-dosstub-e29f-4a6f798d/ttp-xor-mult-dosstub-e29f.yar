rule TTP_XOR_MULT_DOSStub_e29f {
  strings:
    $key_e29f = { b6 f7 [2] c2 ef [2] 85 ed [2] c2 fc [2] 8c f0 [2] 80 fa [2] 97 f1 [2] 8c bf [2] b1 }

  condition:
    any of them
}