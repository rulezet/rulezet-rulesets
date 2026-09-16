rule TTP_XOR_MULT_DOSStub_8b9f {
  strings:
    $key_8b9f = { df f7 [2] ab ef [2] ec ed [2] ab fc [2] e5 f0 [2] e9 fa [2] fe f1 [2] e5 bf [2] d8 }

  condition:
    any of them
}