rule TTP_XOR_MULT_DOSStub_4a1e {
  strings:
    $key_4a1e = { 1e 76 [2] 6a 6e [2] 2d 6c [2] 6a 7d [2] 24 71 [2] 28 7b [2] 3f 70 [2] 24 3e [2] 19 }

  condition:
    any of them
}