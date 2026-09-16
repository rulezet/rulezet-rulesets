rule TTP_XOR_MULT_DOSStub_e100 {
  strings:
    $key_e100 = { b5 68 [2] c1 70 [2] 86 72 [2] c1 63 [2] 8f 6f [2] 83 65 [2] 94 6e [2] 8f 20 [2] b2 }

  condition:
    any of them
}