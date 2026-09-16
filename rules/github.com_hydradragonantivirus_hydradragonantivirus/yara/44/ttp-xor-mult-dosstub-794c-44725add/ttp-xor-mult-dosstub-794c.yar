rule TTP_XOR_MULT_DOSStub_794c {
  strings:
    $key_794c = { 2d 24 [2] 59 3c [2] 1e 3e [2] 59 2f [2] 17 23 [2] 1b 29 [2] 0c 22 [2] 17 6c [2] 2a }

  condition:
    any of them
}