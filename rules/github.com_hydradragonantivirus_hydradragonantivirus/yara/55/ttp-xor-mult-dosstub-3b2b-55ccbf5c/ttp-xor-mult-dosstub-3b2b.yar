rule TTP_XOR_MULT_DOSStub_3b2b {
  strings:
    $key_3b2b = { 6f 43 [2] 1b 5b [2] 5c 59 [2] 1b 48 [2] 55 44 [2] 59 4e [2] 4e 45 [2] 55 0b [2] 68 }

  condition:
    any of them
}