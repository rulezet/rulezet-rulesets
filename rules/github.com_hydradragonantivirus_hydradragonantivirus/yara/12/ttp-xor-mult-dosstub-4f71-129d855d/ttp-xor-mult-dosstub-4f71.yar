rule TTP_XOR_MULT_DOSStub_4f71 {
  strings:
    $key_4f71 = { 1b 19 [2] 6f 01 [2] 28 03 [2] 6f 12 [2] 21 1e [2] 2d 14 [2] 3a 1f [2] 21 51 [2] 1c }

  condition:
    any of them
}