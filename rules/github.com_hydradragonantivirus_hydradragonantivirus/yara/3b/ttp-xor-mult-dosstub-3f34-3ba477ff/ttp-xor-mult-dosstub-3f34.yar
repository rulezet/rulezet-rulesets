rule TTP_XOR_MULT_DOSStub_3f34 {
  strings:
    $key_3f34 = { 6b 5c [2] 1f 44 [2] 58 46 [2] 1f 57 [2] 51 5b [2] 5d 51 [2] 4a 5a [2] 51 14 [2] 6c }

  condition:
    any of them
}