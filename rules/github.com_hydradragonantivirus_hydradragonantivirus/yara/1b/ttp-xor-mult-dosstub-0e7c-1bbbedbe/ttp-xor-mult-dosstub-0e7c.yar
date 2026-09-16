rule TTP_XOR_MULT_DOSStub_0e7c {
  strings:
    $key_0e7c = { 5a 14 [2] 2e 0c [2] 69 0e [2] 2e 1f [2] 60 13 [2] 6c 19 [2] 7b 12 [2] 60 5c [2] 5d }

  condition:
    any of them
}