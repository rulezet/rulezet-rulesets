rule TTP_XOR_MULT_DOSStub_e99f {
  strings:
    $key_e99f = { bd f7 [2] c9 ef [2] 8e ed [2] c9 fc [2] 87 f0 [2] 8b fa [2] 9c f1 [2] 87 bf [2] ba }

  condition:
    any of them
}