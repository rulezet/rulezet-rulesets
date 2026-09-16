rule TTP_XOR_MULT_DOSStub_267c {
  strings:
    $key_267c = { 72 14 [2] 06 0c [2] 41 0e [2] 06 1f [2] 48 13 [2] 44 19 [2] 53 12 [2] 48 5c [2] 75 }

  condition:
    any of them
}