rule TTP_XOR_MULT_DOSStub_dadd {
  strings:
    $key_dadd = { 8e b5 [2] fa ad [2] bd af [2] fa be [2] b4 b2 [2] b8 b8 [2] af b3 [2] b4 fd [2] 89 }

  condition:
    any of them
}