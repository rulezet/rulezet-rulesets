rule TTP_XOR_MULT_DOSStub_e120 {
  strings:
    $key_e120 = { b5 48 [2] c1 50 [2] 86 52 [2] c1 43 [2] 8f 4f [2] 83 45 [2] 94 4e [2] 8f 00 [2] b2 }

  condition:
    any of them
}