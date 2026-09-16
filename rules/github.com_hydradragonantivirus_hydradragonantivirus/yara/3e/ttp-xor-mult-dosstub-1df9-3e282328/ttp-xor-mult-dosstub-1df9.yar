rule TTP_XOR_MULT_DOSStub_1df9 {
  strings:
    $key_1df9 = { 49 91 [2] 3d 89 [2] 7a 8b [2] 3d 9a [2] 73 96 [2] 7f 9c [2] 68 97 [2] 73 d9 [2] 4e }

  condition:
    any of them
}