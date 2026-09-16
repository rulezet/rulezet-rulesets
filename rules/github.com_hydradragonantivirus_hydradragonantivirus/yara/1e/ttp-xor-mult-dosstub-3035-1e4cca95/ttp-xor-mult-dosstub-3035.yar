rule TTP_XOR_MULT_DOSStub_3035 {
  strings:
    $key_3035 = { 64 5d [2] 10 45 [2] 57 47 [2] 10 56 [2] 5e 5a [2] 52 50 [2] 45 5b [2] 5e 15 [2] 63 }

  condition:
    any of them
}