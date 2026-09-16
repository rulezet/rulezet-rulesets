rule TTP_XOR_MULT_DOSStub_5d2e {
  strings:
    $key_5d2e = { 09 46 [2] 7d 5e [2] 3a 5c [2] 7d 4d [2] 33 41 [2] 3f 4b [2] 28 40 [2] 33 0e [2] 0e }

  condition:
    any of them
}