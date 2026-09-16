rule TTP_XOR_MULT_DOSStub_1d00 {
  strings:
    $key_1d00 = { 49 68 [2] 3d 70 [2] 7a 72 [2] 3d 63 [2] 73 6f [2] 7f 65 [2] 68 6e [2] 73 20 [2] 4e }

  condition:
    any of them
}