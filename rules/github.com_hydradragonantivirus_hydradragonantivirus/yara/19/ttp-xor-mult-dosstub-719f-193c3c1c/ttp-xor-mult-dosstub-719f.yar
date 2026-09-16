rule TTP_XOR_MULT_DOSStub_719f {
  strings:
    $key_719f = { 25 f7 [2] 51 ef [2] 16 ed [2] 51 fc [2] 1f f0 [2] 13 fa [2] 04 f1 [2] 1f bf [2] 22 }

  condition:
    any of them
}