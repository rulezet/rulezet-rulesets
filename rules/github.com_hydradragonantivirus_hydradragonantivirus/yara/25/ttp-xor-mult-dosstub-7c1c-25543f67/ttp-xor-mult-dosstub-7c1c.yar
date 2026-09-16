rule TTP_XOR_MULT_DOSStub_7c1c {
  strings:
    $key_7c1c = { 28 74 [2] 5c 6c [2] 1b 6e [2] 5c 7f [2] 12 73 [2] 1e 79 [2] 09 72 [2] 12 3c [2] 2f }

  condition:
    any of them
}