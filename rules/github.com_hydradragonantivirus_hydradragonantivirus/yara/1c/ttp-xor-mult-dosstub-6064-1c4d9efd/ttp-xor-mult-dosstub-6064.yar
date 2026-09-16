rule TTP_XOR_MULT_DOSStub_6064 {
  strings:
    $key_6064 = { 34 0c [2] 40 14 [2] 07 16 [2] 40 07 [2] 0e 0b [2] 02 01 [2] 15 0a [2] 0e 44 [2] 33 }

  condition:
    any of them
}