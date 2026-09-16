rule TTP_XOR_MULT_DOSStub_4f02 {
  strings:
    $key_4f02 = { 1b 6a [2] 6f 72 [2] 28 70 [2] 6f 61 [2] 21 6d [2] 2d 67 [2] 3a 6c [2] 21 22 [2] 1c }

  condition:
    any of them
}