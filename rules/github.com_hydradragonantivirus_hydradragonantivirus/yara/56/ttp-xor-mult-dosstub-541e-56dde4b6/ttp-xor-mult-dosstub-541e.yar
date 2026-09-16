rule TTP_XOR_MULT_DOSStub_541e {
  strings:
    $key_541e = { 00 76 [2] 74 6e [2] 33 6c [2] 74 7d [2] 3a 71 [2] 36 7b [2] 21 70 [2] 3a 3e [2] 07 }

  condition:
    any of them
}