rule TTP_XOR_MULT_DOSStub_2f15 {
  strings:
    $key_2f15 = { 7b 7d [2] 0f 65 [2] 48 67 [2] 0f 76 [2] 41 7a [2] 4d 70 [2] 5a 7b [2] 41 35 [2] 7c }

  condition:
    any of them
}