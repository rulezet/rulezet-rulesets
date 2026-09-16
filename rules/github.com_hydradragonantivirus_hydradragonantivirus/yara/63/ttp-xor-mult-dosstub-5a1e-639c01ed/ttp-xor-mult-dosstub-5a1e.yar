rule TTP_XOR_MULT_DOSStub_5a1e {
  strings:
    $key_5a1e = { 0e 76 [2] 7a 6e [2] 3d 6c [2] 7a 7d [2] 34 71 [2] 38 7b [2] 2f 70 [2] 34 3e [2] 09 }

  condition:
    any of them
}