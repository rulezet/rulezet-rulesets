rule TTP_XOR_MULT_DOSStub_1df0 {
  strings:
    $key_1df0 = { 49 98 [2] 3d 80 [2] 7a 82 [2] 3d 93 [2] 73 9f [2] 7f 95 [2] 68 9e [2] 73 d0 [2] 4e }

  condition:
    any of them
}