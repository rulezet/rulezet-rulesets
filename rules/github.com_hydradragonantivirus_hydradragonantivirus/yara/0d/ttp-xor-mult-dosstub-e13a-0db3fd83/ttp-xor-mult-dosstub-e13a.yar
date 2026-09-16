rule TTP_XOR_MULT_DOSStub_e13a {
  strings:
    $key_e13a = { b5 52 [2] c1 4a [2] 86 48 [2] c1 59 [2] 8f 55 [2] 83 5f [2] 94 54 [2] 8f 1a [2] b2 }

  condition:
    any of them
}