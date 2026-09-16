rule TTP_XOR_MULT_DOSStub_1de3 {
  strings:
    $key_1de3 = { 49 8b [2] 3d 93 [2] 7a 91 [2] 3d 80 [2] 73 8c [2] 7f 86 [2] 68 8d [2] 73 c3 [2] 4e }

  condition:
    any of them
}