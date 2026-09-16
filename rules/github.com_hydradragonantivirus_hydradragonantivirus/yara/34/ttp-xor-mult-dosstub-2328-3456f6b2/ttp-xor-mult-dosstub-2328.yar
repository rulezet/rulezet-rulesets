rule TTP_XOR_MULT_DOSStub_2328 {
  strings:
    $key_2328 = { 77 40 [2] 03 58 [2] 44 5a [2] 03 4b [2] 4d 47 [2] 41 4d [2] 56 46 [2] 4d 08 [2] 70 }

  condition:
    any of them
}