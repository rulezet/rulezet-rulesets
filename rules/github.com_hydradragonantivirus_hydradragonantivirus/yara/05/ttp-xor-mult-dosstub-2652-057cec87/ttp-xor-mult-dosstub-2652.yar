rule TTP_XOR_MULT_DOSStub_2652 {
  strings:
    $key_2652 = { 72 3a [2] 06 22 [2] 41 20 [2] 06 31 [2] 48 3d [2] 44 37 [2] 53 3c [2] 48 72 [2] 75 }

  condition:
    any of them
}