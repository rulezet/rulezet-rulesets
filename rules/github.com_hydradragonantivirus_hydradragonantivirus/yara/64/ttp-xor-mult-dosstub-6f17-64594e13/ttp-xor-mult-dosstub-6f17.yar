rule TTP_XOR_MULT_DOSStub_6f17 {
  strings:
    $key_6f17 = { 3b 7f [2] 4f 67 [2] 08 65 [2] 4f 74 [2] 01 78 [2] 0d 72 [2] 1a 79 [2] 01 37 [2] 3c }

  condition:
    any of them
}