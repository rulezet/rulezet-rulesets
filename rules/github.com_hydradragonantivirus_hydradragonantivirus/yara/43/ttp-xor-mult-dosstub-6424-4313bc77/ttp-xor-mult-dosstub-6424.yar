rule TTP_XOR_MULT_DOSStub_6424 {
  strings:
    $key_6424 = { 30 4c [2] 44 54 [2] 03 56 [2] 44 47 [2] 0a 4b [2] 06 41 [2] 11 4a [2] 0a 04 [2] 37 }

  condition:
    any of them
}