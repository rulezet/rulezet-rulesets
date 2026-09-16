rule TTP_XOR_MULT_DOSStub_2635 {
  strings:
    $key_2635 = { 72 5d [2] 06 45 [2] 41 47 [2] 06 56 [2] 48 5a [2] 44 50 [2] 53 5b [2] 48 15 [2] 75 }

  condition:
    any of them
}