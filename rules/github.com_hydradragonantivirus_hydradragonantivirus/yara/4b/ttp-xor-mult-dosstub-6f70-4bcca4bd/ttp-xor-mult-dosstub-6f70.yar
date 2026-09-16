rule TTP_XOR_MULT_DOSStub_6f70 {
  strings:
    $key_6f70 = { 3b 18 [2] 4f 00 [2] 08 02 [2] 4f 13 [2] 01 1f [2] 0d 15 [2] 1a 1e [2] 01 50 [2] 3c }

  condition:
    any of them
}