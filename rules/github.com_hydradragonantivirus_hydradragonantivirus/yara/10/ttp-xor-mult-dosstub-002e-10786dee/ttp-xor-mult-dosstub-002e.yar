rule TTP_XOR_MULT_DOSStub_002e {
  strings:
    $key_002e = { 54 46 [2] 20 5e [2] 67 5c [2] 20 4d [2] 6e 41 [2] 62 4b [2] 75 40 [2] 6e 0e [2] 53 }

  condition:
    any of them
}