rule TTP_XOR_MULT_DOSStub_1a1b {
  strings:
    $key_1a1b = { 4e 73 [2] 3a 6b [2] 7d 69 [2] 3a 78 [2] 74 74 [2] 78 7e [2] 6f 75 [2] 74 3b [2] 49 }

  condition:
    any of them
}