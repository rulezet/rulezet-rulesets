rule TTP_XOR_MULT_DOSStub_2b9f {
  strings:
    $key_2b9f = { 7f f7 [2] 0b ef [2] 4c ed [2] 0b fc [2] 45 f0 [2] 49 fa [2] 5e f1 [2] 45 bf [2] 78 }

  condition:
    any of them
}