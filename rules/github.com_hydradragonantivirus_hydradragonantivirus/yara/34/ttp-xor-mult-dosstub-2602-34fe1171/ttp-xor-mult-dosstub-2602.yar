rule TTP_XOR_MULT_DOSStub_2602 {
  strings:
    $key_2602 = { 72 6a [2] 06 72 [2] 41 70 [2] 06 61 [2] 48 6d [2] 44 67 [2] 53 6c [2] 48 22 [2] 75 }

  condition:
    any of them
}