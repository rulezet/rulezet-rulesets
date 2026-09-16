rule TTP_XOR_MULT_DOSStub_1f66 {
  strings:
    $key_1f66 = { 4b 0e [2] 3f 16 [2] 78 14 [2] 3f 05 [2] 71 09 [2] 7d 03 [2] 6a 08 [2] 71 46 [2] 4c }

  condition:
    any of them
}