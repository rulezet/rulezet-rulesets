rule TTP_XOR_MULT_DOSStub_4d27 {
  strings:
    $key_4d27 = { 19 4f [2] 6d 57 [2] 2a 55 [2] 6d 44 [2] 23 48 [2] 2f 42 [2] 38 49 [2] 23 07 [2] 1e }

  condition:
    any of them
}