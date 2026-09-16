rule TTP_XOR_MULT_DOSStub_519f {
  strings:
    $key_519f = { 05 f7 [2] 71 ef [2] 36 ed [2] 71 fc [2] 3f f0 [2] 33 fa [2] 24 f1 [2] 3f bf [2] 02 }

  condition:
    any of them
}