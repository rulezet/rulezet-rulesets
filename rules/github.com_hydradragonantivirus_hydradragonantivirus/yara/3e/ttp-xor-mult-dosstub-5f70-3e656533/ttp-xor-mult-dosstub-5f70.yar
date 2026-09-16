rule TTP_XOR_MULT_DOSStub_5f70 {
  strings:
    $key_5f70 = { 0b 18 [2] 7f 00 [2] 38 02 [2] 7f 13 [2] 31 1f [2] 3d 15 [2] 2a 1e [2] 31 50 [2] 0c }

  condition:
    any of them
}