rule TTP_XOR_MULT_DOSStub_723e {
  strings:
    $key_723e = { 26 56 [2] 52 4e [2] 15 4c [2] 52 5d [2] 1c 51 [2] 10 5b [2] 07 50 [2] 1c 1e [2] 21 }

  condition:
    any of them
}