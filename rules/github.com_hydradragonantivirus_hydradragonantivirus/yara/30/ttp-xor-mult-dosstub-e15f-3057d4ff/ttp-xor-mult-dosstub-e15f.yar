rule TTP_XOR_MULT_DOSStub_e15f {
  strings:
    $key_e15f = { b5 37 [2] c1 2f [2] 86 2d [2] c1 3c [2] 8f 30 [2] 83 3a [2] 94 31 [2] 8f 7f [2] b2 }

  condition:
    any of them
}