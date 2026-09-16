rule TTP_XOR_MULT_DOSStub_337e {
  strings:
    $key_337e = { 67 16 [2] 13 0e [2] 54 0c [2] 13 1d [2] 5d 11 [2] 51 1b [2] 46 10 [2] 5d 5e [2] 60 }

  condition:
    any of them
}