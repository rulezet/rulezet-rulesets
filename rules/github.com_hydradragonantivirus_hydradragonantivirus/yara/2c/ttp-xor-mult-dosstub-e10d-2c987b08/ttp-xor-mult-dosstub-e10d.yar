rule TTP_XOR_MULT_DOSStub_e10d {
  strings:
    $key_e10d = { b5 65 [2] c1 7d [2] 86 7f [2] c1 6e [2] 8f 62 [2] 83 68 [2] 94 63 [2] 8f 2d [2] b2 }

  condition:
    any of them
}