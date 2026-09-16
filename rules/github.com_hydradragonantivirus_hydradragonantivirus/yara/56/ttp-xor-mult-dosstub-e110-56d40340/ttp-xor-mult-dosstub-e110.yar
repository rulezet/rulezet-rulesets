rule TTP_XOR_MULT_DOSStub_e110 {
  strings:
    $key_e110 = { b5 78 [2] c1 60 [2] 86 62 [2] c1 73 [2] 8f 7f [2] 83 75 [2] 94 7e [2] 8f 30 [2] b2 }

  condition:
    any of them
}