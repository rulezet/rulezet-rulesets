rule TTP_XOR_MULT_DOSStub_427c {
  strings:
    $key_427c = { 16 14 [2] 62 0c [2] 25 0e [2] 62 1f [2] 2c 13 [2] 20 19 [2] 37 12 [2] 2c 5c [2] 11 }

  condition:
    any of them
}