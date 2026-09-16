rule TTP_XOR_MULT_DOSStub_1d27 {
  strings:
    $key_1d27 = { 49 4f [2] 3d 57 [2] 7a 55 [2] 3d 44 [2] 73 48 [2] 7f 42 [2] 68 49 [2] 73 07 [2] 4e }

  condition:
    any of them
}