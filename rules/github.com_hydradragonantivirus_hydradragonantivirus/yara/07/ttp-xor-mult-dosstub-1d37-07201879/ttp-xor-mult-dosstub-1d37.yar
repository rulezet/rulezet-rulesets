rule TTP_XOR_MULT_DOSStub_1d37 {
  strings:
    $key_1d37 = { 49 5f [2] 3d 47 [2] 7a 45 [2] 3d 54 [2] 73 58 [2] 7f 52 [2] 68 59 [2] 73 17 [2] 4e }

  condition:
    any of them
}