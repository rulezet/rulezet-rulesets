rule TTP_XOR_MULT_DOSStub_6f05 {
  strings:
    $key_6f05 = { 3b 6d [2] 4f 75 [2] 08 77 [2] 4f 66 [2] 01 6a [2] 0d 60 [2] 1a 6b [2] 01 25 [2] 3c }

  condition:
    any of them
}