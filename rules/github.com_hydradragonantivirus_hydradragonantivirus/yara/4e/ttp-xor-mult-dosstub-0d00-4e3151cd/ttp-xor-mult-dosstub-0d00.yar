rule TTP_XOR_MULT_DOSStub_0d00 {
  strings:
    $key_0d00 = { 59 68 [2] 2d 70 [2] 6a 72 [2] 2d 63 [2] 63 6f [2] 6f 65 [2] 78 6e [2] 63 20 [2] 5e }

  condition:
    any of them
}