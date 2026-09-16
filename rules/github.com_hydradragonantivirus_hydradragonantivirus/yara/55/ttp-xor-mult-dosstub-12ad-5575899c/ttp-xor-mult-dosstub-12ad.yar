rule TTP_XOR_MULT_DOSStub_12ad {
  strings:
    $key_12ad = { 46 c5 [2] 32 dd [2] 75 df [2] 32 ce [2] 7c c2 [2] 70 c8 [2] 67 c3 [2] 7c 8d [2] 41 }

  condition:
    any of them
}