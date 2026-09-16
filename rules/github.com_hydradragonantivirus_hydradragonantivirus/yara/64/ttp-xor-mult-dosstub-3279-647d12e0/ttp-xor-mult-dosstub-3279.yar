rule TTP_XOR_MULT_DOSStub_3279 {
  strings:
    $key_3279 = { 66 11 [2] 12 09 [2] 55 0b [2] 12 1a [2] 5c 16 [2] 50 1c [2] 47 17 [2] 5c 59 [2] 61 }

  condition:
    any of them
}