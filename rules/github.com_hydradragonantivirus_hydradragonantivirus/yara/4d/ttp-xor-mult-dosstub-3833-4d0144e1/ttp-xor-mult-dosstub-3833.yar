rule TTP_XOR_MULT_DOSStub_3833 {
  strings:
    $key_3833 = { 6c 5b [2] 18 43 [2] 5f 41 [2] 18 50 [2] 56 5c [2] 5a 56 [2] 4d 5d [2] 56 13 [2] 6b }

  condition:
    any of them
}