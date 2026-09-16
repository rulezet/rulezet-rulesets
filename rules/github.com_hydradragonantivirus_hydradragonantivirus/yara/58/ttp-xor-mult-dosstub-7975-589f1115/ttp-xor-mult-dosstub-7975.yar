rule TTP_XOR_MULT_DOSStub_7975 {
  strings:
    $key_7975 = { 2d 1d [2] 59 05 [2] 1e 07 [2] 59 16 [2] 17 1a [2] 1b 10 [2] 0c 1b [2] 17 55 [2] 2a }

  condition:
    any of them
}