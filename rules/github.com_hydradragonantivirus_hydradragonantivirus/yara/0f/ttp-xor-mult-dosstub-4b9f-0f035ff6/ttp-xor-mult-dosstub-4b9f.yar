rule TTP_XOR_MULT_DOSStub_4b9f {
  strings:
    $key_4b9f = { 1f f7 [2] 6b ef [2] 2c ed [2] 6b fc [2] 25 f0 [2] 29 fa [2] 3e f1 [2] 25 bf [2] 18 }

  condition:
    any of them
}