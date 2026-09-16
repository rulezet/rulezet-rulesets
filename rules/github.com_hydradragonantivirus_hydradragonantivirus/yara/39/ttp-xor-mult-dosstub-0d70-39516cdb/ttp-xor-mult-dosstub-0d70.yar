rule TTP_XOR_MULT_DOSStub_0d70 {
  strings:
    $key_0d70 = { 59 18 [2] 2d 00 [2] 6a 02 [2] 2d 13 [2] 63 1f [2] 6f 15 [2] 78 1e [2] 63 50 [2] 5e }

  condition:
    any of them
}