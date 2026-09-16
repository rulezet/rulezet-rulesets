rule TTP_XOR_MULT_DOSStub_1d41 {
  strings:
    $key_1d41 = { 49 29 [2] 3d 31 [2] 7a 33 [2] 3d 22 [2] 73 2e [2] 7f 24 [2] 68 2f [2] 73 61 [2] 4e }

  condition:
    any of them
}