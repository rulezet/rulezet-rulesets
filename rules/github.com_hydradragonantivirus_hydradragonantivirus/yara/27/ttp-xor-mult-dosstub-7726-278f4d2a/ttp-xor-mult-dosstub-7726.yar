rule TTP_XOR_MULT_DOSStub_7726 {
  strings:
    $key_7726 = { 23 4e [2] 57 56 [2] 10 54 [2] 57 45 [2] 19 49 [2] 15 43 [2] 02 48 [2] 19 06 [2] 24 }

  condition:
    any of them
}