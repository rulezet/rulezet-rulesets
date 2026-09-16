rule TTP_XOR_MULT_DOSStub_3817 {
  strings:
    $key_3817 = { 6c 7f [2] 18 67 [2] 5f 65 [2] 18 74 [2] 56 78 [2] 5a 72 [2] 4d 79 [2] 56 37 [2] 6b }

  condition:
    any of them
}