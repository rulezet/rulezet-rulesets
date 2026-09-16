rule TTP_XOR_MULT_DOSStub_4c1c {
  strings:
    $key_4c1c = { 18 74 [2] 6c 6c [2] 2b 6e [2] 6c 7f [2] 22 73 [2] 2e 79 [2] 39 72 [2] 22 3c [2] 1f }

  condition:
    any of them
}