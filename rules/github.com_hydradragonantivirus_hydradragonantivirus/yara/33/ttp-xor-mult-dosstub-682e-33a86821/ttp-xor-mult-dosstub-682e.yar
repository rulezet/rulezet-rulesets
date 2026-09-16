rule TTP_XOR_MULT_DOSStub_682e {
  strings:
    $key_682e = { 3c 46 [2] 48 5e [2] 0f 5c [2] 48 4d [2] 06 41 [2] 0a 4b [2] 1d 40 [2] 06 0e [2] 3b }

  condition:
    any of them
}