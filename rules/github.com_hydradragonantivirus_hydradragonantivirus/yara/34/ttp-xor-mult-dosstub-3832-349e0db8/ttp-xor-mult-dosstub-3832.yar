rule TTP_XOR_MULT_DOSStub_3832 {
  strings:
    $key_3832 = { 6c 5a [2] 18 42 [2] 5f 40 [2] 18 51 [2] 56 5d [2] 5a 57 [2] 4d 5c [2] 56 12 [2] 6b }

  condition:
    any of them
}