rule TTP_XOR_MULT_DOSStub_3f15 {
  strings:
    $key_3f15 = { 6b 7d [2] 1f 65 [2] 58 67 [2] 1f 76 [2] 51 7a [2] 5d 70 [2] 4a 7b [2] 51 35 [2] 6c }

  condition:
    any of them
}