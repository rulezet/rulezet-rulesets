rule TTP_XOR_MULT_DOSStub_0926 {
  strings:
    $key_0926 = { 5d 4e [2] 29 56 [2] 6e 54 [2] 29 45 [2] 67 49 [2] 6b 43 [2] 7c 48 [2] 67 06 [2] 5a }

  condition:
    any of them
}