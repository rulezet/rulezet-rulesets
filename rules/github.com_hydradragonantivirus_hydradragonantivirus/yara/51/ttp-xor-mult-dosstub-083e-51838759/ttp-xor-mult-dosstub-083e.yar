rule TTP_XOR_MULT_DOSStub_083e {
  strings:
    $key_083e = { 5c 56 [2] 28 4e [2] 6f 4c [2] 28 5d [2] 66 51 [2] 6a 5b [2] 7d 50 [2] 66 1e [2] 5b }

  condition:
    any of them
}