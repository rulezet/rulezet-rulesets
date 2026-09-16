rule TTP_XOR_MULT_DOSStub_3f62 {
  strings:
    $key_3f62 = { 6b 0a [2] 1f 12 [2] 58 10 [2] 1f 01 [2] 51 0d [2] 5d 07 [2] 4a 0c [2] 51 42 [2] 6c }

  condition:
    any of them
}