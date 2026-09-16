rule TTP_XOR_MULT_DOSStub_3235 {
  strings:
    $key_3235 = { 66 5d [2] 12 45 [2] 55 47 [2] 12 56 [2] 5c 5a [2] 50 50 [2] 47 5b [2] 5c 15 [2] 61 }

  condition:
    any of them
}