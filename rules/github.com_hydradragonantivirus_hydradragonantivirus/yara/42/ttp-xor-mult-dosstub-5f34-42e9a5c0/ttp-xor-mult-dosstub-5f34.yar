rule TTP_XOR_MULT_DOSStub_5f34 {
  strings:
    $key_5f34 = { 0b 5c [2] 7f 44 [2] 38 46 [2] 7f 57 [2] 31 5b [2] 3d 51 [2] 2a 5a [2] 31 14 [2] 0c }

  condition:
    any of them
}