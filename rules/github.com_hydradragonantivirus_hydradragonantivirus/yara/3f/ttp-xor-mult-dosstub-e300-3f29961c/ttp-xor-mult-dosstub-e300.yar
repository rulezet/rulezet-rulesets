rule TTP_XOR_MULT_DOSStub_e300 {
  strings:
    $key_e300 = { b7 68 [2] c3 70 [2] 84 72 [2] c3 63 [2] 8d 6f [2] 81 65 [2] 96 6e [2] 8d 20 [2] b0 }

  condition:
    any of them
}