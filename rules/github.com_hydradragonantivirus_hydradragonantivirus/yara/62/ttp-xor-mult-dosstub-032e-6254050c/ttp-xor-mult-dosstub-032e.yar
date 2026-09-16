rule TTP_XOR_MULT_DOSStub_032e {
  strings:
    $key_032e = { 57 46 [2] 23 5e [2] 64 5c [2] 23 4d [2] 6d 41 [2] 61 4b [2] 76 40 [2] 6d 0e [2] 50 }

  condition:
    any of them
}