rule TTP_XOR_MULT_DOSStub_283e {
  strings:
    $key_283e = { 7c 56 [2] 08 4e [2] 4f 4c [2] 08 5d [2] 46 51 [2] 4a 5b [2] 5d 50 [2] 46 1e [2] 7b }

  condition:
    any of them
}