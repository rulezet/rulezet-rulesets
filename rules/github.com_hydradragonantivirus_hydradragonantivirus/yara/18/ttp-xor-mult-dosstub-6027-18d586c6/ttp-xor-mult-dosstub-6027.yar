rule TTP_XOR_MULT_DOSStub_6027 {
  strings:
    $key_6027 = { 34 4f [2] 40 57 [2] 07 55 [2] 40 44 [2] 0e 48 [2] 02 42 [2] 15 49 [2] 0e 07 [2] 33 }

  condition:
    any of them
}