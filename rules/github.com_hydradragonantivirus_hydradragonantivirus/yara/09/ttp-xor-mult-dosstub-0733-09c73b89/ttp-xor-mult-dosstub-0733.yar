rule TTP_XOR_MULT_DOSStub_0733 {
  strings:
    $key_0733 = { 53 5b [2] 27 43 [2] 60 41 [2] 27 50 [2] 69 5c [2] 65 56 [2] 72 5d [2] 69 13 [2] 54 }

  condition:
    any of them
}