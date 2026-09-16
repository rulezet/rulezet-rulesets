rule TTP_XOR_MULT_DOSStub_2a2e {
  strings:
    $key_2a2e = { 7e 46 [2] 0a 5e [2] 4d 5c [2] 0a 4d [2] 44 41 [2] 48 4b [2] 5f 40 [2] 44 0e [2] 79 }

  condition:
    any of them
}