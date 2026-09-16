rule TTP_XOR_MULT_DOSStub_0e26 {
  strings:
    $key_0e26 = { 5a 4e [2] 2e 56 [2] 69 54 [2] 2e 45 [2] 60 49 [2] 6c 43 [2] 7b 48 [2] 60 06 [2] 5d }

  condition:
    any of them
}