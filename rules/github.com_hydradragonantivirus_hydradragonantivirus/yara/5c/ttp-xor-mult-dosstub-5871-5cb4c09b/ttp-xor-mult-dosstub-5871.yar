rule TTP_XOR_MULT_DOSStub_5871 {
  strings:
    $key_5871 = { 0c 19 [2] 78 01 [2] 3f 03 [2] 78 12 [2] 36 1e [2] 3a 14 [2] 2d 1f [2] 36 51 [2] 0b }

  condition:
    any of them
}