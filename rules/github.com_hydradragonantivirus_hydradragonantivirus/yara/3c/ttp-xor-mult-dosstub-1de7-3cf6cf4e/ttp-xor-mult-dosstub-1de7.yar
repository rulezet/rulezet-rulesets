rule TTP_XOR_MULT_DOSStub_1de7 {
  strings:
    $key_1de7 = { 49 8f [2] 3d 97 [2] 7a 95 [2] 3d 84 [2] 73 88 [2] 7f 82 [2] 68 89 [2] 73 c7 [2] 4e }

  condition:
    any of them
}