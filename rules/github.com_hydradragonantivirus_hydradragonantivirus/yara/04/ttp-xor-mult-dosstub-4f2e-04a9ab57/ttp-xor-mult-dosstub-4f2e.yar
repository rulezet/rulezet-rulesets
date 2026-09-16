rule TTP_XOR_MULT_DOSStub_4f2e {
  strings:
    $key_4f2e = { 1b 46 [2] 6f 5e [2] 28 5c [2] 6f 4d [2] 21 41 [2] 2d 4b [2] 3a 40 [2] 21 0e [2] 1c }

  condition:
    any of them
}