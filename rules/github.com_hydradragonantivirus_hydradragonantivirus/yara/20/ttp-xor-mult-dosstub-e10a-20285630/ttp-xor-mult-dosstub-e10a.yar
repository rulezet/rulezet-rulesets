rule TTP_XOR_MULT_DOSStub_e10a {
  strings:
    $key_e10a = { b5 62 [2] c1 7a [2] 86 78 [2] c1 69 [2] 8f 65 [2] 83 6f [2] 94 64 [2] 8f 2a [2] b2 }

  condition:
    any of them
}