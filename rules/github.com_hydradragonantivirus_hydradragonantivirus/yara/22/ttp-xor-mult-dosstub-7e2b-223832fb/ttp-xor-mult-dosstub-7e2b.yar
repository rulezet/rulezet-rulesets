rule TTP_XOR_MULT_DOSStub_7e2b {
  strings:
    $key_7e2b = { 2a 43 [2] 5e 5b [2] 19 59 [2] 5e 48 [2] 10 44 [2] 1c 4e [2] 0b 45 [2] 10 0b [2] 2d }

  condition:
    any of them
}