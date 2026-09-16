rule TTP_XOR_MULT_DOSStub_e000 {
  strings:
    $key_e000 = { b4 68 [2] c0 70 [2] 87 72 [2] c0 63 [2] 8e 6f [2] 82 65 [2] 95 6e [2] 8e 20 [2] b3 }

  condition:
    any of them
}