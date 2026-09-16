rule TTP_XOR_MULT_DOSStub_7d27 {
  strings:
    $key_7d27 = { 29 4f [2] 5d 57 [2] 1a 55 [2] 5d 44 [2] 13 48 [2] 1f 42 [2] 08 49 [2] 13 07 [2] 2e }

  condition:
    any of them
}