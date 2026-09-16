rule TTP_XOR_MULT_DOSStub_059f {
  strings:
    $key_059f = { 51 f7 [2] 25 ef [2] 62 ed [2] 25 fc [2] 6b f0 [2] 67 fa [2] 70 f1 [2] 6b bf [2] 56 }

  condition:
    any of them
}