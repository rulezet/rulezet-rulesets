rule TTP_XOR_MULT_DOSStub_4816 {
  strings:
    $key_4816 = { 1c 7e [2] 68 66 [2] 2f 64 [2] 68 75 [2] 26 79 [2] 2a 73 [2] 3d 78 [2] 26 36 [2] 1b }

  condition:
    any of them
}