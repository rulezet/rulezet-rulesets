rule TTP_XOR_MULT_DOSStub_e13d {
  strings:
    $key_e13d = { b5 55 [2] c1 4d [2] 86 4f [2] c1 5e [2] 8f 52 [2] 83 58 [2] 94 53 [2] 8f 1d [2] b2 }

  condition:
    any of them
}