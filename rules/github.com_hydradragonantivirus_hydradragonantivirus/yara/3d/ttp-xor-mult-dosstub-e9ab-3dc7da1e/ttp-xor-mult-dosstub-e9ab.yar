rule TTP_XOR_MULT_DOSStub_e9ab {
  strings:
    $key_e9ab = { bd c3 [2] c9 db [2] 8e d9 [2] c9 c8 [2] 87 c4 [2] 8b ce [2] 9c c5 [2] 87 8b [2] ba }

  condition:
    any of them
}