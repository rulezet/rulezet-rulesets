rule TTP_XOR_MULT_DOSStub_dc9f {
  strings:
    $key_dc9f = { 88 f7 [2] fc ef [2] bb ed [2] fc fc [2] b2 f0 [2] be fa [2] a9 f1 [2] b2 bf [2] 8f }

  condition:
    any of them
}