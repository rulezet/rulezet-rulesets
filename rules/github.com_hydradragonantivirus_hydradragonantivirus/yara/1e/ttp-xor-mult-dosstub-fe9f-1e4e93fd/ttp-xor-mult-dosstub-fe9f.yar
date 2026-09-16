rule TTP_XOR_MULT_DOSStub_fe9f {
  strings:
    $key_fe9f = { aa f7 [2] de ef [2] 99 ed [2] de fc [2] 90 f0 [2] 9c fa [2] 8b f1 [2] 90 bf [2] ad }

  condition:
    any of them
}