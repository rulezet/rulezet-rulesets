rule TTP_XOR_MULT_DOSStub_2f62 {
  strings:
    $key_2f62 = { 7b 0a [2] 0f 12 [2] 48 10 [2] 0f 01 [2] 41 0d [2] 4d 07 [2] 5a 0c [2] 41 42 [2] 7c }

  condition:
    any of them
}