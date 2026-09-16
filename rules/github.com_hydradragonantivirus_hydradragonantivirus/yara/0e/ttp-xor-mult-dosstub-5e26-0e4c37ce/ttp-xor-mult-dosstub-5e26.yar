rule TTP_XOR_MULT_DOSStub_5e26 {
  strings:
    $key_5e26 = { 0a 4e [2] 7e 56 [2] 39 54 [2] 7e 45 [2] 30 49 [2] 3c 43 [2] 2b 48 [2] 30 06 [2] 0d }

  condition:
    any of them
}