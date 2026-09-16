rule TTP_XOR_MULT_DOSStub_e17b {
  strings:
    $key_e17b = { b5 13 [2] c1 0b [2] 86 09 [2] c1 18 [2] 8f 14 [2] 83 1e [2] 94 15 [2] 8f 5b [2] b2 }

  condition:
    any of them
}