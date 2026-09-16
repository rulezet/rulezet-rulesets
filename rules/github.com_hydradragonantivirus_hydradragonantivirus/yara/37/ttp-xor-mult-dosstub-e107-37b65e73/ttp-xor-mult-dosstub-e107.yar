rule TTP_XOR_MULT_DOSStub_e107 {
  strings:
    $key_e107 = { b5 6f [2] c1 77 [2] 86 75 [2] c1 64 [2] 8f 68 [2] 83 62 [2] 94 69 [2] 8f 27 [2] b2 }

  condition:
    any of them
}