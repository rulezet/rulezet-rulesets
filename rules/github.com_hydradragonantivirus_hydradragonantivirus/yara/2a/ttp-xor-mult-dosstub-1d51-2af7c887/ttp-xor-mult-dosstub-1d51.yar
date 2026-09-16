rule TTP_XOR_MULT_DOSStub_1d51 {
  strings:
    $key_1d51 = { 49 39 [2] 3d 21 [2] 7a 23 [2] 3d 32 [2] 73 3e [2] 7f 34 [2] 68 3f [2] 73 71 [2] 4e }

  condition:
    any of them
}