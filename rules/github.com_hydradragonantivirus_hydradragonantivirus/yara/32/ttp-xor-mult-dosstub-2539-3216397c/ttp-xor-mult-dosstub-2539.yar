rule TTP_XOR_MULT_DOSStub_2539 {
  strings:
    $key_2539 = { 71 51 [2] 05 49 [2] 42 4b [2] 05 5a [2] 4b 56 [2] 47 5c [2] 50 57 [2] 4b 19 [2] 76 }

  condition:
    any of them
}