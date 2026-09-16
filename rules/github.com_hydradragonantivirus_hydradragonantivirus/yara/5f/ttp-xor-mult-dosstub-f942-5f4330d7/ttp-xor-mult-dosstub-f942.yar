rule TTP_XOR_MULT_DOSStub_f942 {
  strings:
    $key_f942 = { ad 2a [2] d9 32 [2] 9e 30 [2] d9 21 [2] 97 2d [2] 9b 27 [2] 8c 2c [2] 97 62 [2] aa }

  condition:
    any of them
}