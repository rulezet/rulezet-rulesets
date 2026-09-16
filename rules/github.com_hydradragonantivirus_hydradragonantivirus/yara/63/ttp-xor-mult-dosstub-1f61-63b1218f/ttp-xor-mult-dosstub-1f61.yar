rule TTP_XOR_MULT_DOSStub_1f61 {
  strings:
    $key_1f61 = { 4b 09 [2] 3f 11 [2] 78 13 [2] 3f 02 [2] 71 0e [2] 7d 04 [2] 6a 0f [2] 71 41 [2] 4c }

  condition:
    any of them
}