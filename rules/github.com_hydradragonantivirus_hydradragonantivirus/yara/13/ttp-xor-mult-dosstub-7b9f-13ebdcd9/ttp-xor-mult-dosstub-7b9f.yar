rule TTP_XOR_MULT_DOSStub_7b9f {
  strings:
    $key_7b9f = { 2f f7 [2] 5b ef [2] 1c ed [2] 5b fc [2] 15 f0 [2] 19 fa [2] 0e f1 [2] 15 bf [2] 28 }

  condition:
    any of them
}