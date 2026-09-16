rule TTP_XOR_MULT_DOSStub_029f {
  strings:
    $key_029f = { 56 f7 [2] 22 ef [2] 65 ed [2] 22 fc [2] 6c f0 [2] 60 fa [2] 77 f1 [2] 6c bf [2] 51 }

  condition:
    any of them
}