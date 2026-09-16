rule TTP_XOR_MULT_DOSStub_0d66 {
  strings:
    $key_0d66 = { 59 0e [2] 2d 16 [2] 6a 14 [2] 2d 05 [2] 63 09 [2] 6f 03 [2] 78 08 [2] 63 46 [2] 5e }

  condition:
    any of them
}