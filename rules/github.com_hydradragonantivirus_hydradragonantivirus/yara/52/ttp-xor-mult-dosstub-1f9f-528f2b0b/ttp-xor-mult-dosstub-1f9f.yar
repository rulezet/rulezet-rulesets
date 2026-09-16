rule TTP_XOR_MULT_DOSStub_1f9f {
  strings:
    $key_1f9f = { 4b f7 [2] 3f ef [2] 78 ed [2] 3f fc [2] 71 f0 [2] 7d fa [2] 6a f1 [2] 71 bf [2] 4c }

  condition:
    any of them
}