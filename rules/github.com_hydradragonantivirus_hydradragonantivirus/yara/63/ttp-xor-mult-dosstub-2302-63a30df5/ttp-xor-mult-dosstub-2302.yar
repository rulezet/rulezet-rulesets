rule TTP_XOR_MULT_DOSStub_2302 {
  strings:
    $key_2302 = { 77 6a [2] 03 72 [2] 44 70 [2] 03 61 [2] 4d 6d [2] 41 67 [2] 56 6c [2] 4d 22 [2] 70 }

  condition:
    any of them
}