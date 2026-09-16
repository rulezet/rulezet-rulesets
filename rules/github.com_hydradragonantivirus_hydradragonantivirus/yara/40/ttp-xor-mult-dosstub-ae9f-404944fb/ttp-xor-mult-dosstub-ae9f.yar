rule TTP_XOR_MULT_DOSStub_ae9f {
  strings:
    $key_ae9f = { fa f7 [2] 8e ef [2] c9 ed [2] 8e fc [2] c0 f0 [2] cc fa [2] db f1 [2] c0 bf [2] fd }

  condition:
    any of them
}