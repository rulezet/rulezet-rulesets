rule TTP_XOR_MULT_DOSStub_189f {
  strings:
    $key_189f = { 4c f7 [2] 38 ef [2] 7f ed [2] 38 fc [2] 76 f0 [2] 7a fa [2] 6d f1 [2] 76 bf [2] 4b }

  condition:
    any of them
}