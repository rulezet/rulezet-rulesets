rule TTP_XOR_MULT_DOSStub_4031 {
  strings:
    $key_4031 = { 14 59 [2] 60 41 [2] 27 43 [2] 60 52 [2] 2e 5e [2] 22 54 [2] 35 5f [2] 2e 11 [2] 13 }

  condition:
    any of them
}