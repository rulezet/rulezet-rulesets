rule TTP_XOR_MULT_DOSStub_5f76 {
  strings:
    $key_5f76 = { 0b 1e [2] 7f 06 [2] 38 04 [2] 7f 15 [2] 31 19 [2] 3d 13 [2] 2a 18 [2] 31 56 [2] 0c }

  condition:
    any of them
}