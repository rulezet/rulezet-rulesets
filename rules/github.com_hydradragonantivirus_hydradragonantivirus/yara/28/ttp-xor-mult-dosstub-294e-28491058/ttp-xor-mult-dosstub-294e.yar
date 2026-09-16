rule TTP_XOR_MULT_DOSStub_294e {
  strings:
    $key_294e = { 7d 26 [2] 09 3e [2] 4e 3c [2] 09 2d [2] 47 21 [2] 4b 2b [2] 5c 20 [2] 47 6e [2] 7a }

  condition:
    any of them
}