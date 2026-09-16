rule TTP_XOR_MULT_DOSStub_4f9f {
  strings:
    $key_4f9f = { 1b f7 [2] 6f ef [2] 28 ed [2] 6f fc [2] 21 f0 [2] 2d fa [2] 3a f1 [2] 21 bf [2] 1c }

  condition:
    any of them
}