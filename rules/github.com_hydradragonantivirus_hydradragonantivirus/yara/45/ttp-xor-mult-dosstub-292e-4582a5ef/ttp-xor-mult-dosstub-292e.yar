rule TTP_XOR_MULT_DOSStub_292e {
  strings:
    $key_292e = { 7d 46 [2] 09 5e [2] 4e 5c [2] 09 4d [2] 47 41 [2] 4b 4b [2] 5c 40 [2] 47 0e [2] 7a }

  condition:
    any of them
}