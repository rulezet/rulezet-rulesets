rule TTP_XOR_MULT_DOSStub_5bad {
  strings:
    $key_5bad = { 0f c5 [2] 7b dd [2] 3c df [2] 7b ce [2] 35 c2 [2] 39 c8 [2] 2e c3 [2] 35 8d [2] 08 }

  condition:
    any of them
}