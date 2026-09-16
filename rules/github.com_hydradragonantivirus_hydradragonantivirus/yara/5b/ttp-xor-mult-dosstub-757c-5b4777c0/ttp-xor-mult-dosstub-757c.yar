rule TTP_XOR_MULT_DOSStub_757c {
  strings:
    $key_757c = { 21 14 [2] 55 0c [2] 12 0e [2] 55 1f [2] 1b 13 [2] 17 19 [2] 00 12 [2] 1b 5c [2] 26 }

  condition:
    any of them
}