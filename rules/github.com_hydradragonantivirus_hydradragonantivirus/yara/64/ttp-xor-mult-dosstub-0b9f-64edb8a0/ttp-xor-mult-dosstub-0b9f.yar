rule TTP_XOR_MULT_DOSStub_0b9f {
  strings:
    $key_0b9f = { 5f f7 [2] 2b ef [2] 6c ed [2] 2b fc [2] 65 f0 [2] 69 fa [2] 7e f1 [2] 65 bf [2] 58 }

  condition:
    any of them
}