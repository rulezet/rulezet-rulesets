rule TTP_XOR_MULT_DOSStub_e15d {
  strings:
    $key_e15d = { b5 35 [2] c1 2d [2] 86 2f [2] c1 3e [2] 8f 32 [2] 83 38 [2] 94 33 [2] 8f 7d [2] b2 }

  condition:
    any of them
}