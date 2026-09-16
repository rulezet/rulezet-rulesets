rule TTP_XOR_MULT_DOSStub_7162 {
  strings:
    $key_7162 = { 25 0a [2] 51 12 [2] 16 10 [2] 51 01 [2] 1f 0d [2] 13 07 [2] 04 0c [2] 1f 42 [2] 22 }

  condition:
    any of them
}