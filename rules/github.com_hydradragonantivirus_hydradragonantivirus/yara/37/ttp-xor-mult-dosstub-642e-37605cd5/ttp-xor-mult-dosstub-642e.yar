rule TTP_XOR_MULT_DOSStub_642e {
  strings:
    $key_642e = { 30 46 [2] 44 5e [2] 03 5c [2] 44 4d [2] 0a 41 [2] 06 4b [2] 11 40 [2] 0a 0e [2] 37 }

  condition:
    any of them
}