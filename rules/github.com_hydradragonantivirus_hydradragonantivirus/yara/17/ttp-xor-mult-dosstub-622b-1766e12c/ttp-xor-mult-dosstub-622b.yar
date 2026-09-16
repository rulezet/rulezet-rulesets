rule TTP_XOR_MULT_DOSStub_622b {
  strings:
    $key_622b = { 36 43 [2] 42 5b [2] 05 59 [2] 42 48 [2] 0c 44 [2] 00 4e [2] 17 45 [2] 0c 0b [2] 31 }

  condition:
    any of them
}