rule TTP_XOR_MULT_DOSStub_4524 {
  strings:
    $key_4524 = { 11 4c [2] 65 54 [2] 22 56 [2] 65 47 [2] 2b 4b [2] 27 41 [2] 30 4a [2] 2b 04 [2] 16 }

  condition:
    any of them
}