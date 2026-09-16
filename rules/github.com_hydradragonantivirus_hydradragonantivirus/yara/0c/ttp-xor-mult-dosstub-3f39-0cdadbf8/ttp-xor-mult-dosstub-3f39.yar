rule TTP_XOR_MULT_DOSStub_3f39 {
  strings:
    $key_3f39 = { 6b 51 [2] 1f 49 [2] 58 4b [2] 1f 5a [2] 51 56 [2] 5d 5c [2] 4a 57 [2] 51 19 [2] 6c }

  condition:
    any of them
}