rule TTP_XOR_MULT_DOSStub_1d20 {
  strings:
    $key_1d20 = { 49 48 [2] 3d 50 [2] 7a 52 [2] 3d 43 [2] 73 4f [2] 7f 45 [2] 68 4e [2] 73 00 [2] 4e }

  condition:
    any of them
}