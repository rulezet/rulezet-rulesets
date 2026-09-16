rule TTP_XOR_MULT_DOSStub_791c {
  strings:
    $key_791c = { 2d 74 [2] 59 6c [2] 1e 6e [2] 59 7f [2] 17 73 [2] 1b 79 [2] 0c 72 [2] 17 3c [2] 2a }

  condition:
    any of them
}