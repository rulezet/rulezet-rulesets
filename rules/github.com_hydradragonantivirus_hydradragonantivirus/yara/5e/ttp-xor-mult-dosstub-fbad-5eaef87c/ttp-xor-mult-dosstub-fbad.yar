rule TTP_XOR_MULT_DOSStub_fbad {
  strings:
    $key_fbad = { af c5 [2] db dd [2] 9c df [2] db ce [2] 95 c2 [2] 99 c8 [2] 8e c3 [2] 95 8d [2] a8 }

  condition:
    any of them
}