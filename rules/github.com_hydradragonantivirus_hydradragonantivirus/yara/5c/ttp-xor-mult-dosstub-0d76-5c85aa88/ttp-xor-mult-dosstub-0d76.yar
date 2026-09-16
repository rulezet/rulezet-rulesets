rule TTP_XOR_MULT_DOSStub_0d76 {
  strings:
    $key_0d76 = { 59 1e [2] 2d 06 [2] 6a 04 [2] 2d 15 [2] 63 19 [2] 6f 13 [2] 78 18 [2] 63 56 [2] 5e }

  condition:
    any of them
}