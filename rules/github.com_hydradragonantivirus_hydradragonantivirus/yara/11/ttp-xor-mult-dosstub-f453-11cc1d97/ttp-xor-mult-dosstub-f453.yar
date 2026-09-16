rule TTP_XOR_MULT_DOSStub_f453 {
  strings:
    $key_f453 = { a0 3b [2] d4 23 [2] 93 21 [2] d4 30 [2] 9a 3c [2] 96 36 [2] 81 3d [2] 9a 73 [2] a7 }

  condition:
    any of them
}