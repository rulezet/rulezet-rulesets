rule TTP_XOR_MULT_DOSStub_4b2e {
  strings:
    $key_4b2e = { 1f 46 [2] 6b 5e [2] 2c 5c [2] 6b 4d [2] 25 41 [2] 29 4b [2] 3e 40 [2] 25 0e [2] 18 }

  condition:
    any of them
}