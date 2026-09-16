rule TTP_XOR_MULT_DOSStub_e14a {
  strings:
    $key_e14a = { b5 22 [2] c1 3a [2] 86 38 [2] c1 29 [2] 8f 25 [2] 83 2f [2] 94 24 [2] 8f 6a [2] b2 }

  condition:
    any of them
}