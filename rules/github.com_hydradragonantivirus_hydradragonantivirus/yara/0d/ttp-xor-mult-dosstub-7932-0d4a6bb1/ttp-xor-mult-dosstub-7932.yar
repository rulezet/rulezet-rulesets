rule TTP_XOR_MULT_DOSStub_7932 {
  strings:
    $key_7932 = { 2d 5a [2] 59 42 [2] 1e 40 [2] 59 51 [2] 17 5d [2] 1b 57 [2] 0c 5c [2] 17 12 [2] 2a }

  condition:
    any of them
}