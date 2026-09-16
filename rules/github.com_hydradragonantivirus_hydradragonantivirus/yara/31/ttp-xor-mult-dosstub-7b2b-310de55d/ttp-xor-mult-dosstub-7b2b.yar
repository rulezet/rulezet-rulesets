rule TTP_XOR_MULT_DOSStub_7b2b {
  strings:
    $key_7b2b = { 2f 43 [2] 5b 5b [2] 1c 59 [2] 5b 48 [2] 15 44 [2] 19 4e [2] 0e 45 [2] 15 0b [2] 28 }

  condition:
    any of them
}