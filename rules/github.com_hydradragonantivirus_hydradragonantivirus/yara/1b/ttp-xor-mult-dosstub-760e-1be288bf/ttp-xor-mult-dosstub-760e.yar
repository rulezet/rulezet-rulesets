rule TTP_XOR_MULT_DOSStub_760e {
  strings:
    $key_760e = { 22 66 [2] 56 7e [2] 11 7c [2] 56 6d [2] 18 61 [2] 14 6b [2] 03 60 [2] 18 2e [2] 25 }

  condition:
    any of them
}