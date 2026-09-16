rule TTP_XOR_MULT_DOSStub_5e2b {
  strings:
    $key_5e2b = { 0a 43 [2] 7e 5b [2] 39 59 [2] 7e 48 [2] 30 44 [2] 3c 4e [2] 2b 45 [2] 30 0b [2] 0d }

  condition:
    any of them
}