rule TTP_XOR_MULT_DOSStub_1d10 {
  strings:
    $key_1d10 = { 49 78 [2] 3d 60 [2] 7a 62 [2] 3d 73 [2] 73 7f [2] 7f 75 [2] 68 7e [2] 73 30 [2] 4e }

  condition:
    any of them
}