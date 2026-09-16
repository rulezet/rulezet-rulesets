rule TTP_XOR_MULT_DOSStub_274c {
  strings:
    $key_274c = { 73 24 [2] 07 3c [2] 40 3e [2] 07 2f [2] 49 23 [2] 45 29 [2] 52 22 [2] 49 6c [2] 74 }

  condition:
    any of them
}