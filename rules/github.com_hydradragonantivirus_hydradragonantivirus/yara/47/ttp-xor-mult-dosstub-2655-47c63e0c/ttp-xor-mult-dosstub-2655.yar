rule TTP_XOR_MULT_DOSStub_2655 {
  strings:
    $key_2655 = { 72 3d [2] 06 25 [2] 41 27 [2] 06 36 [2] 48 3a [2] 44 30 [2] 53 3b [2] 48 75 [2] 75 }

  condition:
    any of them
}