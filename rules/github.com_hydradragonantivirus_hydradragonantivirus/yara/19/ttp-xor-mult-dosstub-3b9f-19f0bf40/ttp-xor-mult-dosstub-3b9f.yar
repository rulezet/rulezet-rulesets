rule TTP_XOR_MULT_DOSStub_3b9f {
  strings:
    $key_3b9f = { 6f f7 [2] 1b ef [2] 5c ed [2] 1b fc [2] 55 f0 [2] 59 fa [2] 4e f1 [2] 55 bf [2] 68 }

  condition:
    any of them
}