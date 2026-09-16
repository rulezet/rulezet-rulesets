rule TTP_XOR_MULT_DOSStub_1e7c {
  strings:
    $key_1e7c = { 4a 14 [2] 3e 0c [2] 79 0e [2] 3e 1f [2] 70 13 [2] 7c 19 [2] 6b 12 [2] 70 5c [2] 4d }

  condition:
    any of them
}