rule TTP_XOR_MULT_DOSStub_1a2b {
  strings:
    $key_1a2b = { 4e 43 [2] 3a 5b [2] 7d 59 [2] 3a 48 [2] 74 44 [2] 78 4e [2] 6f 45 [2] 74 0b [2] 49 }

  condition:
    any of them
}