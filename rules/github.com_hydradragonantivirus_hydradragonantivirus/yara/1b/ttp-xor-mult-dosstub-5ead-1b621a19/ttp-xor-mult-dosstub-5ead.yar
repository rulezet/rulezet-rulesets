rule TTP_XOR_MULT_DOSStub_5ead {
  strings:
    $key_5ead = { 0a c5 [2] 7e dd [2] 39 df [2] 7e ce [2] 30 c2 [2] 3c c8 [2] 2b c3 [2] 30 8d [2] 0d }

  condition:
    any of them
}