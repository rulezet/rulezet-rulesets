rule TTP_XOR_MULT_DOSStub_4a3e {
  strings:
    $key_4a3e = { 1e 56 [2] 6a 4e [2] 2d 4c [2] 6a 5d [2] 24 51 [2] 28 5b [2] 3f 50 [2] 24 1e [2] 19 }

  condition:
    any of them
}