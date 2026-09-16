rule TTP_XOR_MULT_DOSStub_aa9f {
  strings:
    $key_aa9f = { fe f7 [2] 8a ef [2] cd ed [2] 8a fc [2] c4 f0 [2] c8 fa [2] df f1 [2] c4 bf [2] f9 }

  condition:
    any of them
}