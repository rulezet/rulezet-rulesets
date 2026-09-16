rule TTP_XOR_MULT_DOSStub_b99f {
  strings:
    $key_b99f = { ed f7 [2] 99 ef [2] de ed [2] 99 fc [2] d7 f0 [2] db fa [2] cc f1 [2] d7 bf [2] ea }

  condition:
    any of them
}