rule TTP_XOR_MULT_DOSStub_5a00 {
  strings:
    $key_5a00 = { 0e 68 [2] 7a 70 [2] 3d 72 [2] 7a 63 [2] 34 6f [2] 38 65 [2] 2f 6e [2] 34 20 [2] 09 }

  condition:
    any of them
}