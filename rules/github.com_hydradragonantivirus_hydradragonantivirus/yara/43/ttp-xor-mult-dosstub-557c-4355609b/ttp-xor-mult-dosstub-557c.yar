rule TTP_XOR_MULT_DOSStub_557c {
  strings:
    $key_557c = { 01 14 [2] 75 0c [2] 32 0e [2] 75 1f [2] 3b 13 [2] 37 19 [2] 20 12 [2] 3b 5c [2] 06 }

  condition:
    any of them
}