rule TTP_XOR_MULT_DOSStub_ab9f {
  strings:
    $key_ab9f = { ff f7 [2] 8b ef [2] cc ed [2] 8b fc [2] c5 f0 [2] c9 fa [2] de f1 [2] c5 bf [2] f8 }

  condition:
    any of them
}