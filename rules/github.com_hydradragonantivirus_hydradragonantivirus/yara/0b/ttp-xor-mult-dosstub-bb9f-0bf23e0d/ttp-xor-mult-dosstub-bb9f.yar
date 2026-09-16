rule TTP_XOR_MULT_DOSStub_bb9f {
  strings:
    $key_bb9f = { ef f7 [2] 9b ef [2] dc ed [2] 9b fc [2] d5 f0 [2] d9 fa [2] ce f1 [2] d5 bf [2] e8 }

  condition:
    any of them
}