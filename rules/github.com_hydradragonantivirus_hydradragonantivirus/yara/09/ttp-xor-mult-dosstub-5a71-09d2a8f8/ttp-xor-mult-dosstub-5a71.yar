rule TTP_XOR_MULT_DOSStub_5a71 {
  strings:
    $key_5a71 = { 0e 19 [2] 7a 01 [2] 3d 03 [2] 7a 12 [2] 34 1e [2] 38 14 [2] 2f 1f [2] 34 51 [2] 09 }

  condition:
    any of them
}