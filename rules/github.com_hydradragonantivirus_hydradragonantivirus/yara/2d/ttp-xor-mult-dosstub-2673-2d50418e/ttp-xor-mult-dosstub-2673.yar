rule TTP_XOR_MULT_DOSStub_2673 {
  strings:
    $key_2673 = { 72 1b [2] 06 03 [2] 41 01 [2] 06 10 [2] 48 1c [2] 44 16 [2] 53 1d [2] 48 53 [2] 75 }

  condition:
    any of them
}