rule TTP_XOR_MULT_DOSStub_4d7c {
  strings:
    $key_4d7c = { 19 14 [2] 6d 0c [2] 2a 0e [2] 6d 1f [2] 23 13 [2] 2f 19 [2] 38 12 [2] 23 5c [2] 1e }

  condition:
    any of them
}