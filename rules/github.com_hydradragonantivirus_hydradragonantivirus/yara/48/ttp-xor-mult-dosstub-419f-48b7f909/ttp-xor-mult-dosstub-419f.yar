rule TTP_XOR_MULT_DOSStub_419f {
  strings:
    $key_419f = { 15 f7 [2] 61 ef [2] 26 ed [2] 61 fc [2] 2f f0 [2] 23 fa [2] 34 f1 [2] 2f bf [2] 12 }

  condition:
    any of them
}