rule TTP_XOR_MULT_DOSStub_5f9f {
  strings:
    $key_5f9f = { 0b f7 [2] 7f ef [2] 38 ed [2] 7f fc [2] 31 f0 [2] 3d fa [2] 2a f1 [2] 31 bf [2] 0c }

  condition:
    any of them
}