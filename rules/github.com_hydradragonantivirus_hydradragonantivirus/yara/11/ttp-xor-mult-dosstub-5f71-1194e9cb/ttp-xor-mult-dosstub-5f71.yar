rule TTP_XOR_MULT_DOSStub_5f71 {
  strings:
    $key_5f71 = { 0b 19 [2] 7f 01 [2] 38 03 [2] 7f 12 [2] 31 1e [2] 3d 14 [2] 2a 1f [2] 31 51 [2] 0c }

  condition:
    any of them
}