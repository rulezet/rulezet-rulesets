rule TTP_XOR_MULT_DOSStub_5a35 {
  strings:
    $key_5a35 = { 0e 5d [2] 7a 45 [2] 3d 47 [2] 7a 56 [2] 34 5a [2] 38 50 [2] 2f 5b [2] 34 15 [2] 09 }

  condition:
    any of them
}