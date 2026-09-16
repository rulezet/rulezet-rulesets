rule TTP_XOR_MULT_DOSStub_1de0 {
  strings:
    $key_1de0 = { 49 88 [2] 3d 90 [2] 7a 92 [2] 3d 83 [2] 73 8f [2] 7f 85 [2] 68 8e [2] 73 c0 [2] 4e }

  condition:
    any of them
}