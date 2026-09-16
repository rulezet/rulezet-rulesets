rule TTP_XOR_MULT_DOSStub_7927 {
  strings:
    $key_7927 = { 2d 4f [2] 59 57 [2] 1e 55 [2] 59 44 [2] 17 48 [2] 1b 42 [2] 0c 49 [2] 17 07 [2] 2a }

  condition:
    any of them
}