rule TTP_XOR_MULT_DOSStub_2322 {
  strings:
    $key_2322 = { 77 4a [2] 03 52 [2] 44 50 [2] 03 41 [2] 4d 4d [2] 41 47 [2] 56 4c [2] 4d 02 [2] 70 }

  condition:
    any of them
}