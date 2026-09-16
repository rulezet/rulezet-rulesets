rule TTP_XOR_MULT_DOSStub_6f15 {
  strings:
    $key_6f15 = { 3b 7d [2] 4f 65 [2] 08 67 [2] 4f 76 [2] 01 7a [2] 0d 70 [2] 1a 7b [2] 01 35 [2] 3c }

  condition:
    any of them
}