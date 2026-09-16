rule TTP_XOR_MULT_DOSStub_7d31 {
  strings:
    $key_7d31 = { 29 59 [2] 5d 41 [2] 1a 43 [2] 5d 52 [2] 13 5e [2] 1f 54 [2] 08 5f [2] 13 11 [2] 2e }

  condition:
    any of them
}