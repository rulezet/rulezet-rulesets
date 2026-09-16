rule TTP_XOR_MULT_DOSStub_1b2b {
  strings:
    $key_1b2b = { 4f 43 [2] 3b 5b [2] 7c 59 [2] 3b 48 [2] 75 44 [2] 79 4e [2] 6e 45 [2] 75 0b [2] 48 }

  condition:
    any of them
}