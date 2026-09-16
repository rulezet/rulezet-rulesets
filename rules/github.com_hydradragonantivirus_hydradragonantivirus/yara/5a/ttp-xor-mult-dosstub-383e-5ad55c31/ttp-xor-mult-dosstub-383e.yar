rule TTP_XOR_MULT_DOSStub_383e {
  strings:
    $key_383e = { 6c 56 [2] 18 4e [2] 5f 4c [2] 18 5d [2] 56 51 [2] 5a 5b [2] 4d 50 [2] 56 1e [2] 6b }

  condition:
    any of them
}