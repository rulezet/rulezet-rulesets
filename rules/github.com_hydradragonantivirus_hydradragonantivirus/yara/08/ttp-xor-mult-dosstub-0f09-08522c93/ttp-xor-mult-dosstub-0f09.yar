rule TTP_XOR_MULT_DOSStub_0f09 {
  strings:
    $key_0f09 = { 5b 61 [2] 2f 79 [2] 68 7b [2] 2f 6a [2] 61 66 [2] 6d 6c [2] 7a 67 [2] 61 29 [2] 5c }

  condition:
    any of them
}