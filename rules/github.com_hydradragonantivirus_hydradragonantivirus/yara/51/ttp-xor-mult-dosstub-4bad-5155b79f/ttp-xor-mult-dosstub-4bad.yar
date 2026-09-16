rule TTP_XOR_MULT_DOSStub_4bad {
  strings:
    $key_4bad = { 1f c5 [2] 6b dd [2] 2c df [2] 6b ce [2] 25 c2 [2] 29 c8 [2] 3e c3 [2] 25 8d [2] 18 }

  condition:
    any of them
}