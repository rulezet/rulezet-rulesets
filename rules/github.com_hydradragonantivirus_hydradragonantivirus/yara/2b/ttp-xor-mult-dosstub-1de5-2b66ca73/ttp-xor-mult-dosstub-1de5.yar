rule TTP_XOR_MULT_DOSStub_1de5 {
  strings:
    $key_1de5 = { 49 8d [2] 3d 95 [2] 7a 97 [2] 3d 86 [2] 73 8a [2] 7f 80 [2] 68 8b [2] 73 c5 [2] 4e }

  condition:
    any of them
}