rule TTP_XOR_MULT_DOSStub_5f66 {
  strings:
    $key_5f66 = { 0b 0e [2] 7f 16 [2] 38 14 [2] 7f 05 [2] 31 09 [2] 3d 03 [2] 2a 08 [2] 31 46 [2] 0c }

  condition:
    any of them
}