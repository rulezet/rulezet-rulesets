rule TTP_XOR_MULT_DOSStub_4435 {
  strings:
    $key_4435 = { 10 5d [2] 64 45 [2] 23 47 [2] 64 56 [2] 2a 5a [2] 26 50 [2] 31 5b [2] 2a 15 [2] 17 }

  condition:
    any of them
}