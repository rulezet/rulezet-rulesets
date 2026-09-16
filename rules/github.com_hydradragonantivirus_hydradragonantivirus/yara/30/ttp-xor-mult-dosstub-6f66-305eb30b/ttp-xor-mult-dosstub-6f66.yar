rule TTP_XOR_MULT_DOSStub_6f66 {
  strings:
    $key_6f66 = { 3b 0e [2] 4f 16 [2] 08 14 [2] 4f 05 [2] 01 09 [2] 0d 03 [2] 1a 08 [2] 01 46 [2] 3c }

  condition:
    any of them
}