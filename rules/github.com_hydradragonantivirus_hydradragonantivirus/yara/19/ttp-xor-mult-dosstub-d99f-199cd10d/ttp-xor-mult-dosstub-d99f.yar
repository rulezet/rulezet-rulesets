rule TTP_XOR_MULT_DOSStub_d99f {
  strings:
    $key_d99f = { 8d f7 [2] f9 ef [2] be ed [2] f9 fc [2] b7 f0 [2] bb fa [2] ac f1 [2] b7 bf [2] 8a }

  condition:
    any of them
}