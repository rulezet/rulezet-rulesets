rule TTP_XOR_MULT_DOSStub_4035 {
  strings:
    $key_4035 = { 14 5d [2] 60 45 [2] 27 47 [2] 60 56 [2] 2e 5a [2] 22 50 [2] 35 5b [2] 2e 15 [2] 13 }

  condition:
    any of them
}