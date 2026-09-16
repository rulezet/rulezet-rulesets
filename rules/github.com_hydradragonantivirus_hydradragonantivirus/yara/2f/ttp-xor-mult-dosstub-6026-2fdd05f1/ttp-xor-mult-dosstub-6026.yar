rule TTP_XOR_MULT_DOSStub_6026 {
  strings:
    $key_6026 = { 34 4e [2] 40 56 [2] 07 54 [2] 40 45 [2] 0e 49 [2] 02 43 [2] 15 48 [2] 0e 06 [2] 33 }

  condition:
    any of them
}