rule TTP_XOR_MULT_DOSStub_f968 {
  strings:
    $key_f968 = { ad 00 [2] d9 18 [2] 9e 1a [2] d9 0b [2] 97 07 [2] 9b 0d [2] 8c 06 [2] 97 48 [2] aa }

  condition:
    any of them
}