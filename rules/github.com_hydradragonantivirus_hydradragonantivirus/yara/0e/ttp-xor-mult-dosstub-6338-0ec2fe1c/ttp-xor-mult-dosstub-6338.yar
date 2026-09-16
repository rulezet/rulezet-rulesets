rule TTP_XOR_MULT_DOSStub_6338 {
  strings:
    $key_6338 = { 37 50 [2] 43 48 [2] 04 4a [2] 43 5b [2] 0d 57 [2] 01 5d [2] 16 56 [2] 0d 18 [2] 30 }

  condition:
    any of them
}