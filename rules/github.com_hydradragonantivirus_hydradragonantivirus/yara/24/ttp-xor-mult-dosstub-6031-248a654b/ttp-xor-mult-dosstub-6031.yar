rule TTP_XOR_MULT_DOSStub_6031 {
  strings:
    $key_6031 = { 34 59 [2] 40 41 [2] 07 43 [2] 40 52 [2] 0e 5e [2] 02 54 [2] 15 5f [2] 0e 11 [2] 33 }

  condition:
    any of them
}