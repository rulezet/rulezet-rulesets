rule TTP_XOR_MULT_DOSStub_323e {
  strings:
    $key_323e = { 66 56 [2] 12 4e [2] 55 4c [2] 12 5d [2] 5c 51 [2] 50 5b [2] 47 50 [2] 5c 1e [2] 61 }

  condition:
    any of them
}