rule TTP_XOR_MULT_DOSStub_f1e0 {
  strings:
    $key_f1e0 = { a5 88 [2] d1 90 [2] 96 92 [2] d1 83 [2] 9f 8f [2] 93 85 [2] 84 8e [2] 9f c0 [2] a2 }

  condition:
    any of them
}