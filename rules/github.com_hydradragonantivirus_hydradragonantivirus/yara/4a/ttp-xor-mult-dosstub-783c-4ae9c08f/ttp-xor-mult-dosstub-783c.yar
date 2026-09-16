rule TTP_XOR_MULT_DOSStub_783c {
  strings:
    $key_783c = { 2c 54 [2] 58 4c [2] 1f 4e [2] 58 5f [2] 16 53 [2] 1a 59 [2] 0d 52 [2] 16 1c [2] 2b }

  condition:
    any of them
}