rule TTP_XOR_MULT_DOSStub_5524 {
  strings:
    $key_5524 = { 01 4c [2] 75 54 [2] 32 56 [2] 75 47 [2] 3b 4b [2] 37 41 [2] 20 4a [2] 3b 04 [2] 06 }

  condition:
    any of them
}