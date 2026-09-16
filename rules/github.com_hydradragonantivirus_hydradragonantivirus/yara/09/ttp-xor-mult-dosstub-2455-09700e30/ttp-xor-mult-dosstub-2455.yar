rule TTP_XOR_MULT_DOSStub_2455 {
  strings:
    $key_2455 = { 70 3d [2] 04 25 [2] 43 27 [2] 04 36 [2] 4a 3a [2] 46 30 [2] 51 3b [2] 4a 75 [2] 77 }

  condition:
    any of them
}