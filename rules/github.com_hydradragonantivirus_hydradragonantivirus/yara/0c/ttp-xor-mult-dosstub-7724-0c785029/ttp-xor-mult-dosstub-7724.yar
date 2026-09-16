rule TTP_XOR_MULT_DOSStub_7724 {
  strings:
    $key_7724 = { 23 4c [2] 57 54 [2] 10 56 [2] 57 47 [2] 19 4b [2] 15 41 [2] 02 4a [2] 19 04 [2] 24 }

  condition:
    any of them
}