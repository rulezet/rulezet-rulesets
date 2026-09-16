rule TTP_XOR_MULT_DOSStub_747c {
  strings:
    $key_747c = { 20 14 [2] 54 0c [2] 13 0e [2] 54 1f [2] 1a 13 [2] 16 19 [2] 01 12 [2] 1a 5c [2] 27 }

  condition:
    any of them
}