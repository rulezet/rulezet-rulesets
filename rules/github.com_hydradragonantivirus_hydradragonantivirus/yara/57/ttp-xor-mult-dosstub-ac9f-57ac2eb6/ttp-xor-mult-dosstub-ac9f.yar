rule TTP_XOR_MULT_DOSStub_ac9f {
  strings:
    $key_ac9f = { f8 f7 [2] 8c ef [2] cb ed [2] 8c fc [2] c2 f0 [2] ce fa [2] d9 f1 [2] c2 bf [2] ff }

  condition:
    any of them
}