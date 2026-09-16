rule TTP_XOR_MULT_DOSStub_5f15 {
  strings:
    $key_5f15 = { 0b 7d [2] 7f 65 [2] 38 67 [2] 7f 76 [2] 31 7a [2] 3d 70 [2] 2a 7b [2] 31 35 [2] 0c }

  condition:
    any of them
}