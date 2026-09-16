rule TTP_XOR_MULT_DOSStub_6f09 {
  strings:
    $key_6f09 = { 3b 61 [2] 4f 79 [2] 08 7b [2] 4f 6a [2] 01 66 [2] 0d 6c [2] 1a 67 [2] 01 29 [2] 3c }

  condition:
    any of them
}