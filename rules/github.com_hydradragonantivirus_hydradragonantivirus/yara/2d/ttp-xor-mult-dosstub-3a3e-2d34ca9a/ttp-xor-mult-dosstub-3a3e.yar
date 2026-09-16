rule TTP_XOR_MULT_DOSStub_3a3e {
  strings:
    $key_3a3e = { 6e 56 [2] 1a 4e [2] 5d 4c [2] 1a 5d [2] 54 51 [2] 58 5b [2] 4f 50 [2] 54 1e [2] 69 }

  condition:
    any of them
}