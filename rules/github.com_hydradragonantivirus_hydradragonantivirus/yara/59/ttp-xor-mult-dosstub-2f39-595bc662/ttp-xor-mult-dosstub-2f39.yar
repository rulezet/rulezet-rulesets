rule TTP_XOR_MULT_DOSStub_2f39 {
  strings:
    $key_2f39 = { 7b 51 [2] 0f 49 [2] 48 4b [2] 0f 5a [2] 41 56 [2] 4d 5c [2] 5a 57 [2] 41 19 [2] 7c }

  condition:
    any of them
}