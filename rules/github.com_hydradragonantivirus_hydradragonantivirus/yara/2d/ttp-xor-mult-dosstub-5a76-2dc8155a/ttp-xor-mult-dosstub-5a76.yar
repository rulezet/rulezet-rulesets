rule TTP_XOR_MULT_DOSStub_5a76 {
  strings:
    $key_5a76 = { 0e 1e [2] 7a 06 [2] 3d 04 [2] 7a 15 [2] 34 19 [2] 38 13 [2] 2f 18 [2] 34 56 [2] 09 }

  condition:
    any of them
}