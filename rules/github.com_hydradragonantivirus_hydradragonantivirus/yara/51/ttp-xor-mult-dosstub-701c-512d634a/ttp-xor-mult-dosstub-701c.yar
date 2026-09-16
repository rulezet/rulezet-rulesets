rule TTP_XOR_MULT_DOSStub_701c {
  strings:
    $key_701c = { 24 74 [2] 50 6c [2] 17 6e [2] 50 7f [2] 1e 73 [2] 12 79 [2] 05 72 [2] 1e 3c [2] 23 }

  condition:
    any of them
}