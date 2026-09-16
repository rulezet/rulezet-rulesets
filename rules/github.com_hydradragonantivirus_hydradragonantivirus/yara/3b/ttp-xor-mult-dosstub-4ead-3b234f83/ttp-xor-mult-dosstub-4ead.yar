rule TTP_XOR_MULT_DOSStub_4ead {
  strings:
    $key_4ead = { 1a c5 [2] 6e dd [2] 29 df [2] 6e ce [2] 20 c2 [2] 2c c8 [2] 3b c3 [2] 20 8d [2] 1d }

  condition:
    any of them
}