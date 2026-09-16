rule TTP_XOR_MULT_DOSStub_2d2e {
  strings:
    $key_2d2e = { 79 46 [2] 0d 5e [2] 4a 5c [2] 0d 4d [2] 43 41 [2] 4f 4b [2] 58 40 [2] 43 0e [2] 7e }

  condition:
    any of them
}