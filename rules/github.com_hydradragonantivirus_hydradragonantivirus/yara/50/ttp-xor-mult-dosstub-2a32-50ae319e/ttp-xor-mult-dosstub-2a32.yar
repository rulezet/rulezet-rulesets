rule TTP_XOR_MULT_DOSStub_2a32 {
  strings:
    $key_2a32 = { 7e 5a [2] 0a 42 [2] 4d 40 [2] 0a 51 [2] 44 5d [2] 48 57 [2] 5f 5c [2] 44 12 [2] 79 }

  condition:
    any of them
}