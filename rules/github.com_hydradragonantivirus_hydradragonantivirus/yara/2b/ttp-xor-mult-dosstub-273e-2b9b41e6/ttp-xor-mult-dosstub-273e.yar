rule TTP_XOR_MULT_DOSStub_273e {
  strings:
    $key_273e = { 73 56 [2] 07 4e [2] 40 4c [2] 07 5d [2] 49 51 [2] 45 5b [2] 52 50 [2] 49 1e [2] 74 }

  condition:
    any of them
}