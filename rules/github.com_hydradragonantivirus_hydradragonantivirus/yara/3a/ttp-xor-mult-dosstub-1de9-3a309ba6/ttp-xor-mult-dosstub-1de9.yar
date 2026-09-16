rule TTP_XOR_MULT_DOSStub_1de9 {
  strings:
    $key_1de9 = { 49 81 [2] 3d 99 [2] 7a 9b [2] 3d 8a [2] 73 86 [2] 7f 8c [2] 68 87 [2] 73 c9 [2] 4e }

  condition:
    any of them
}