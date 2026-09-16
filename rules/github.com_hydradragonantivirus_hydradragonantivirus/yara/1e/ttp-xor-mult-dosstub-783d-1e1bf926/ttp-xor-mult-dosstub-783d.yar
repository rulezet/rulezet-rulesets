rule TTP_XOR_MULT_DOSStub_783d {
  strings:
    $key_783d = { 2c 55 [2] 58 4d [2] 1f 4f [2] 58 5e [2] 16 52 [2] 1a 58 [2] 0d 53 [2] 16 1d [2] 2b }

  condition:
    any of them
}