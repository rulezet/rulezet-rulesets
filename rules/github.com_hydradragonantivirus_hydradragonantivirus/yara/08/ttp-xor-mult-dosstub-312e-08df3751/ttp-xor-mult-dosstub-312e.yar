rule TTP_XOR_MULT_DOSStub_312e {
  strings:
    $key_312e = { 65 46 [2] 11 5e [2] 56 5c [2] 11 4d [2] 5f 41 [2] 53 4b [2] 44 40 [2] 5f 0e [2] 62 }

  condition:
    any of them
}