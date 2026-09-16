rule TTP_XOR_MULT_DOSStub_332b {
  strings:
    $key_332b = { 67 43 [2] 13 5b [2] 54 59 [2] 13 48 [2] 5d 44 [2] 51 4e [2] 46 45 [2] 5d 0b [2] 60 }

  condition:
    any of them
}