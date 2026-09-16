rule TTP_XOR_MULT_DOSStub_1d11 {
  strings:
    $key_1d11 = { 49 79 [2] 3d 61 [2] 7a 63 [2] 3d 72 [2] 73 7e [2] 7f 74 [2] 68 7f [2] 73 31 [2] 4e }

  condition:
    any of them
}