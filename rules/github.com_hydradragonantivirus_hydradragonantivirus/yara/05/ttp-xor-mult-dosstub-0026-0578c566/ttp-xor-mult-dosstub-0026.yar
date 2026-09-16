rule TTP_XOR_MULT_DOSStub_0026 {
  strings:
    $key_0026 = { 54 4e [2] 20 56 [2] 67 54 [2] 20 45 [2] 6e 49 [2] 62 43 [2] 75 48 [2] 6e 06 [2] 53 }

  condition:
    any of them
}