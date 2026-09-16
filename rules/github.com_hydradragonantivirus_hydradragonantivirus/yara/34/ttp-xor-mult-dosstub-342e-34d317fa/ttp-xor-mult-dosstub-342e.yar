rule TTP_XOR_MULT_DOSStub_342e {
  strings:
    $key_342e = { 60 46 [2] 14 5e [2] 53 5c [2] 14 4d [2] 5a 41 [2] 56 4b [2] 41 40 [2] 5a 0e [2] 67 }

  condition:
    any of them
}