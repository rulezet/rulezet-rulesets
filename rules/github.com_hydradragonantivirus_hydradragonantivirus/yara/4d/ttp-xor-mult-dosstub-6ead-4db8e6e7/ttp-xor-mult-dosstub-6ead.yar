rule TTP_XOR_MULT_DOSStub_6ead {
  strings:
    $key_6ead = { 3a c5 [2] 4e dd [2] 09 df [2] 4e ce [2] 00 c2 [2] 0c c8 [2] 1b c3 [2] 00 8d [2] 3d }

  condition:
    any of them
}