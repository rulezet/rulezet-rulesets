rule TTP_XOR_MULT_DOSStub_1d36 {
  strings:
    $key_1d36 = { 49 5e [2] 3d 46 [2] 7a 44 [2] 3d 55 [2] 73 59 [2] 7f 53 [2] 68 58 [2] 73 16 [2] 4e }

  condition:
    any of them
}