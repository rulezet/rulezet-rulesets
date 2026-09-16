rule TTP_XOR_MULT_DOSStub_3f76 {
  strings:
    $key_3f76 = { 6b 1e [2] 1f 06 [2] 58 04 [2] 1f 15 [2] 51 19 [2] 5d 13 [2] 4a 18 [2] 51 56 [2] 6c }

  condition:
    any of them
}