rule TTP_XOR_MULT_DOSStub_7653 {
  strings:
    $key_7653 = { 22 3b [2] 56 23 [2] 11 21 [2] 56 30 [2] 18 3c [2] 14 36 [2] 03 3d [2] 18 73 [2] 25 }

  condition:
    any of them
}