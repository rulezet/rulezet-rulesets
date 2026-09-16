rule TTP_XOR_MULT_DOSStub_1f70 {
  strings:
    $key_1f70 = { 4b 18 [2] 3f 00 [2] 78 02 [2] 3f 13 [2] 71 1f [2] 7d 15 [2] 6a 1e [2] 71 50 [2] 4c }

  condition:
    any of them
}