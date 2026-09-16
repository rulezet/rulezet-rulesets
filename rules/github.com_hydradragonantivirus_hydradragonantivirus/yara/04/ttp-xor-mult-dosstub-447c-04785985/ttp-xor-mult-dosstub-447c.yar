rule TTP_XOR_MULT_DOSStub_447c {
  strings:
    $key_447c = { 10 14 [2] 64 0c [2] 23 0e [2] 64 1f [2] 2a 13 [2] 26 19 [2] 31 12 [2] 2a 5c [2] 17 }

  condition:
    any of them
}