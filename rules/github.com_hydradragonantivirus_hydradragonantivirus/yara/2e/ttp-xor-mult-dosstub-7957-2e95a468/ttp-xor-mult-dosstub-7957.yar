rule TTP_XOR_MULT_DOSStub_7957 {
  strings:
    $key_7957 = { 2d 3f [2] 59 27 [2] 1e 25 [2] 59 34 [2] 17 38 [2] 1b 32 [2] 0c 39 [2] 17 77 [2] 2a }

  condition:
    any of them
}