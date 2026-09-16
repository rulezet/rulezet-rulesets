rule TTP_XOR_MULT_DOSStub_3bad {
  strings:
    $key_3bad = { 6f c5 [2] 1b dd [2] 5c df [2] 1b ce [2] 55 c2 [2] 59 c8 [2] 4e c3 [2] 55 8d [2] 68 }

  condition:
    any of them
}