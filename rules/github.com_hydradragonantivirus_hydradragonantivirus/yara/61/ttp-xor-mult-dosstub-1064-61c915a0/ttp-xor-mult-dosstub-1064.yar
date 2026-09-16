rule TTP_XOR_MULT_DOSStub_1064 {
  strings:
    $key_1064 = { 44 0c [2] 30 14 [2] 77 16 [2] 30 07 [2] 7e 0b [2] 72 01 [2] 65 0a [2] 7e 44 [2] 43 }

  condition:
    any of them
}