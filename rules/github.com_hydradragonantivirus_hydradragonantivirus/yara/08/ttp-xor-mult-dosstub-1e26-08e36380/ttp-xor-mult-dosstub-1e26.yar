rule TTP_XOR_MULT_DOSStub_1e26 {
  strings:
    $key_1e26 = { 4a 4e [2] 3e 56 [2] 79 54 [2] 3e 45 [2] 70 49 [2] 7c 43 [2] 6b 48 [2] 70 06 [2] 4d }

  condition:
    any of them
}