rule TTP_XOR_MULT_DOSStub_6f34 {
  strings:
    $key_6f34 = { 3b 5c [2] 4f 44 [2] 08 46 [2] 4f 57 [2] 01 5b [2] 0d 51 [2] 1a 5a [2] 01 14 [2] 3c }

  condition:
    any of them
}