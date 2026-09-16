rule TTP_XOR_MULT_DOSStub_e011 {
  strings:
    $key_e011 = { b4 79 [2] c0 61 [2] 87 63 [2] c0 72 [2] 8e 7e [2] 82 74 [2] 95 7f [2] 8e 31 [2] b3 }

  condition:
    any of them
}