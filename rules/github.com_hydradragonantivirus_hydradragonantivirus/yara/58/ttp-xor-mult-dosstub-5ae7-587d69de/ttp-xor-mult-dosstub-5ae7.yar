rule TTP_XOR_MULT_DOSStub_5ae7 {
  strings:
    $key_5ae7 = { 0e 8f [2] 7a 97 [2] 3d 95 [2] 7a 84 [2] 34 88 [2] 38 82 [2] 2f 89 [2] 34 c7 [2] 09 }

  condition:
    any of them
}