rule TTP_XOR_MULT_DOSStub_5a33 {
  strings:
    $key_5a33 = { 0e 5b [2] 7a 43 [2] 3d 41 [2] 7a 50 [2] 34 5c [2] 38 56 [2] 2f 5d [2] 34 13 [2] 09 }

  condition:
    any of them
}