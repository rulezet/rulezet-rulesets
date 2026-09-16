rule TTP_XOR_MULT_DOSStub_6435 {
  strings:
    $key_6435 = { 30 5d [2] 44 45 [2] 03 47 [2] 44 56 [2] 0a 5a [2] 06 50 [2] 11 5b [2] 0a 15 [2] 37 }

  condition:
    any of them
}