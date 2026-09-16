rule TTP_XOR_MULT_DOSStub_671e {
  strings:
    $key_671e = { 33 76 [2] 47 6e [2] 00 6c [2] 47 7d [2] 09 71 [2] 05 7b [2] 12 70 [2] 09 3e [2] 34 }

  condition:
    any of them
}