rule TTP_XOR_MULT_DOSStub_129f {
  strings:
    $key_129f = { 46 f7 [2] 32 ef [2] 75 ed [2] 32 fc [2] 7c f0 [2] 70 fa [2] 67 f1 [2] 7c bf [2] 41 }

  condition:
    any of them
}