rule TTP_XOR_MULT_DOSStub_1d07 {
  strings:
    $key_1d07 = { 49 6f [2] 3d 77 [2] 7a 75 [2] 3d 64 [2] 73 68 [2] 7f 62 [2] 68 69 [2] 73 27 [2] 4e }

  condition:
    any of them
}