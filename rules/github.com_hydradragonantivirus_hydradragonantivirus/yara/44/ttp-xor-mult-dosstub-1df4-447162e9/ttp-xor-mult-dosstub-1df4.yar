rule TTP_XOR_MULT_DOSStub_1df4 {
  strings:
    $key_1df4 = { 49 9c [2] 3d 84 [2] 7a 86 [2] 3d 97 [2] 73 9b [2] 7f 91 [2] 68 9a [2] 73 d4 [2] 4e }

  condition:
    any of them
}