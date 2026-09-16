rule TTP_XOR_MULT_DOSStub_294c {
  strings:
    $key_294c = { 7d 24 [2] 09 3c [2] 4e 3e [2] 09 2f [2] 47 23 [2] 4b 29 [2] 5c 22 [2] 47 6c [2] 7a }

  condition:
    any of them
}