rule TTP_XOR_MULT_DOSStub_5a30 {
  strings:
    $key_5a30 = { 0e 58 [2] 7a 40 [2] 3d 42 [2] 7a 53 [2] 34 5f [2] 38 55 [2] 2f 5e [2] 34 10 [2] 09 }

  condition:
    any of them
}