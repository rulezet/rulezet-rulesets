rule TTP_XOR_MULT_DOSStub_e157 {
  strings:
    $key_e157 = { b5 3f [2] c1 27 [2] 86 25 [2] c1 34 [2] 8f 38 [2] 83 32 [2] 94 39 [2] 8f 77 [2] b2 }

  condition:
    any of them
}