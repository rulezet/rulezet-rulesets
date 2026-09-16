rule TTP_XOR_MULT_DOSStub_4026 {
  strings:
    $key_4026 = { 14 4e [2] 60 56 [2] 27 54 [2] 60 45 [2] 2e 49 [2] 22 43 [2] 35 48 [2] 2e 06 [2] 13 }

  condition:
    any of them
}