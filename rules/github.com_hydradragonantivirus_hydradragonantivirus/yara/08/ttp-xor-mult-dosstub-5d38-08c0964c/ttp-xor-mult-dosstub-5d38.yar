rule TTP_XOR_MULT_DOSStub_5d38 {
  strings:
    $key_5d38 = { 09 50 [2] 7d 48 [2] 3a 4a [2] 7d 5b [2] 33 57 [2] 3f 5d [2] 28 56 [2] 33 18 [2] 0e }

  condition:
    any of them
}