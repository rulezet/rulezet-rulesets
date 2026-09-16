rule TTP_XOR_MULT_DOSStub_3b2e {
  strings:
    $key_3b2e = { 6f 46 [2] 1b 5e [2] 5c 5c [2] 1b 4d [2] 55 41 [2] 59 4b [2] 4e 40 [2] 55 0e [2] 68 }

  condition:
    any of them
}