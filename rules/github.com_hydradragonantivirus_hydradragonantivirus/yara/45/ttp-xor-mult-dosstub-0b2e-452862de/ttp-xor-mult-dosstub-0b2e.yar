rule TTP_XOR_MULT_DOSStub_0b2e {
  strings:
    $key_0b2e = { 5f 46 [2] 2b 5e [2] 6c 5c [2] 2b 4d [2] 65 41 [2] 69 4b [2] 7e 40 [2] 65 0e [2] 58 }

  condition:
    any of them
}