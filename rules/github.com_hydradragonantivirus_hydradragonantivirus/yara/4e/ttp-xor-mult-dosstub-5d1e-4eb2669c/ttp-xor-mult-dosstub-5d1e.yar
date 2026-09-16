rule TTP_XOR_MULT_DOSStub_5d1e {
  strings:
    $key_5d1e = { 09 76 [2] 7d 6e [2] 3a 6c [2] 7d 7d [2] 33 71 [2] 3f 7b [2] 28 70 [2] 33 3e [2] 0e }

  condition:
    any of them
}