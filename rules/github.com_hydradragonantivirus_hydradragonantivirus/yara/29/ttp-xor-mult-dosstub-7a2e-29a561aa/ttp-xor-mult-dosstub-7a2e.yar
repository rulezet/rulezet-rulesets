rule TTP_XOR_MULT_DOSStub_7a2e {
  strings:
    $key_7a2e = { 2e 46 [2] 5a 5e [2] 1d 5c [2] 5a 4d [2] 14 41 [2] 18 4b [2] 0f 40 [2] 14 0e [2] 29 }

  condition:
    any of them
}