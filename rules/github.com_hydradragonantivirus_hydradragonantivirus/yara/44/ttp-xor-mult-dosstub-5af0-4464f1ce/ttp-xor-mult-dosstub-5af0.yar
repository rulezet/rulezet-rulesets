rule TTP_XOR_MULT_DOSStub_5af0 {
  strings:
    $key_5af0 = { 0e 98 [2] 7a 80 [2] 3d 82 [2] 7a 93 [2] 34 9f [2] 38 95 [2] 2f 9e [2] 34 d0 [2] 09 }

  condition:
    any of them
}