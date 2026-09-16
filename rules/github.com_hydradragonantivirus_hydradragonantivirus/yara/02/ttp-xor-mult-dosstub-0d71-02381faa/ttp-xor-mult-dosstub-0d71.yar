rule TTP_XOR_MULT_DOSStub_0d71 {
  strings:
    $key_0d71 = { 59 19 [2] 2d 01 [2] 6a 03 [2] 2d 12 [2] 63 1e [2] 6f 14 [2] 78 1f [2] 63 51 [2] 5e }

  condition:
    any of them
}