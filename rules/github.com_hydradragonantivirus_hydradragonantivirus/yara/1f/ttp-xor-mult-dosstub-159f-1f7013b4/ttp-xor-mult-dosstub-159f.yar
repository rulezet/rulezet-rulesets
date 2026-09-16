rule TTP_XOR_MULT_DOSStub_159f {
  strings:
    $key_159f = { 41 f7 [2] 35 ef [2] 72 ed [2] 35 fc [2] 7b f0 [2] 77 fa [2] 60 f1 [2] 7b bf [2] 46 }

  condition:
    any of them
}