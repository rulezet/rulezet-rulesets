rule TTP_XOR_MULT_DOSStub_2c2e {
  strings:
    $key_2c2e = { 78 46 [2] 0c 5e [2] 4b 5c [2] 0c 4d [2] 42 41 [2] 4e 4b [2] 59 40 [2] 42 0e [2] 7f }

  condition:
    any of them
}