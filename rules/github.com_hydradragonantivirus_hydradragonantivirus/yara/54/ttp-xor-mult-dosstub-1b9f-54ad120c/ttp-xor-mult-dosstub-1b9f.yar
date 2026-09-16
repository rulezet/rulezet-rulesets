rule TTP_XOR_MULT_DOSStub_1b9f {
  strings:
    $key_1b9f = { 4f f7 [2] 3b ef [2] 7c ed [2] 3b fc [2] 75 f0 [2] 79 fa [2] 6e f1 [2] 75 bf [2] 48 }

  condition:
    any of them
}