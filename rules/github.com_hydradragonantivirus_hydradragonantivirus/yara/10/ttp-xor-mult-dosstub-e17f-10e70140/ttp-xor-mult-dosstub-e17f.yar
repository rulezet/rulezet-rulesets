rule TTP_XOR_MULT_DOSStub_e17f {
  strings:
    $key_e17f = { b5 17 [2] c1 0f [2] 86 0d [2] c1 1c [2] 8f 10 [2] 83 1a [2] 94 11 [2] 8f 5f [2] b2 }

  condition:
    any of them
}