rule TTP_XOR_MULT_DOSStub_0f15 {
  strings:
    $key_0f15 = { 5b 7d [2] 2f 65 [2] 68 67 [2] 2f 76 [2] 61 7a [2] 6d 70 [2] 7a 7b [2] 61 35 [2] 5c }

  condition:
    any of them
}