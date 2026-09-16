rule TTP_XOR_MULT_DOSStub_0ead {
  strings:
    $key_0ead = { 5a c5 [2] 2e dd [2] 69 df [2] 2e ce [2] 60 c2 [2] 6c c8 [2] 7b c3 [2] 60 8d [2] 5d }

  condition:
    any of them
}