rule TTP_XOR_MULT_DOSStub_3133 {
  strings:
    $key_3133 = { 65 5b [2] 11 43 [2] 56 41 [2] 11 50 [2] 5f 5c [2] 53 56 [2] 44 5d [2] 5f 13 [2] 62 }

  condition:
    any of them
}