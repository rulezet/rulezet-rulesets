rule TTP_XOR_MULT_DOSStub_1b2e {
  strings:
    $key_1b2e = { 4f 46 [2] 3b 5e [2] 7c 5c [2] 3b 4d [2] 75 41 [2] 79 4b [2] 6e 40 [2] 75 0e [2] 48 }

  condition:
    any of them
}