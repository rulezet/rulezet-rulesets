rule TTP_XOR_MULT_DOSStub_1df8 {
  strings:
    $key_1df8 = { 49 90 [2] 3d 88 [2] 7a 8a [2] 3d 9b [2] 73 97 [2] 7f 9d [2] 68 96 [2] 73 d8 [2] 4e }

  condition:
    any of them
}