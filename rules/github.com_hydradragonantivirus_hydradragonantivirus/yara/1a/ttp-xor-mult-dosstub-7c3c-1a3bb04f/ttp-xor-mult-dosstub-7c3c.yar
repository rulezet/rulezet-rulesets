rule TTP_XOR_MULT_DOSStub_7c3c {
  strings:
    $key_7c3c = { 28 54 [2] 5c 4c [2] 1b 4e [2] 5c 5f [2] 12 53 [2] 1e 59 [2] 09 52 [2] 12 1c [2] 2f }

  condition:
    any of them
}