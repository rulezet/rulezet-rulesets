rule TTP_XOR_MULT_DOSStub_5a61 {
  strings:
    $key_5a61 = { 0e 09 [2] 7a 11 [2] 3d 13 [2] 7a 02 [2] 34 0e [2] 38 04 [2] 2f 0f [2] 34 41 [2] 09 }

  condition:
    any of them
}