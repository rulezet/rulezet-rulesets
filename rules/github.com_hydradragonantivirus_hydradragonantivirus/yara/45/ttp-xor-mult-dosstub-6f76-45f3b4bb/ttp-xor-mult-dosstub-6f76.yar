rule TTP_XOR_MULT_DOSStub_6f76 {
  strings:
    $key_6f76 = { 3b 1e [2] 4f 06 [2] 08 04 [2] 4f 15 [2] 01 19 [2] 0d 13 [2] 1a 18 [2] 01 56 [2] 3c }

  condition:
    any of them
}