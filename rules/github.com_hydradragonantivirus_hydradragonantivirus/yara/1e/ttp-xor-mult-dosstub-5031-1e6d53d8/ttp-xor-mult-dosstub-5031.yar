rule TTP_XOR_MULT_DOSStub_5031 {
  strings:
    $key_5031 = { 04 59 [2] 70 41 [2] 37 43 [2] 70 52 [2] 3e 5e [2] 32 54 [2] 25 5f [2] 3e 11 [2] 03 }

  condition:
    any of them
}