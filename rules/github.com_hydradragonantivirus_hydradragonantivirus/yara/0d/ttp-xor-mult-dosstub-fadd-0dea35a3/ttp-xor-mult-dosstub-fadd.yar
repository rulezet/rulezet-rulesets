rule TTP_XOR_MULT_DOSStub_fadd {
  strings:
    $key_fadd = { ae b5 [2] da ad [2] 9d af [2] da be [2] 94 b2 [2] 98 b8 [2] 8f b3 [2] 94 fd [2] a9 }

  condition:
    any of them
}