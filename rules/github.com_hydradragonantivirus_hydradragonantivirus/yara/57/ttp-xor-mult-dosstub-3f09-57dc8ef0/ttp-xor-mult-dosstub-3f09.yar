rule TTP_XOR_MULT_DOSStub_3f09 {
  strings:
    $key_3f09 = { 6b 61 [2] 1f 79 [2] 58 7b [2] 1f 6a [2] 51 66 [2] 5d 6c [2] 4a 67 [2] 51 29 [2] 6c }

  condition:
    any of them
}