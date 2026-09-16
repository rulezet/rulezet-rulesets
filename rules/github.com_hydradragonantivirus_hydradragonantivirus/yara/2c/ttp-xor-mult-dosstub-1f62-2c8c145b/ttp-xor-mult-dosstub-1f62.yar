rule TTP_XOR_MULT_DOSStub_1f62 {
  strings:
    $key_1f62 = { 4b 0a [2] 3f 12 [2] 78 10 [2] 3f 01 [2] 71 0d [2] 7d 07 [2] 6a 0c [2] 71 42 [2] 4c }

  condition:
    any of them
}