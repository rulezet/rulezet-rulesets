rule TTP_XOR_MULT_DOSStub_2f05 {
  strings:
    $key_2f05 = { 7b 6d [2] 0f 75 [2] 48 77 [2] 0f 66 [2] 41 6a [2] 4d 60 [2] 5a 6b [2] 41 25 [2] 7c }

  condition:
    any of them
}