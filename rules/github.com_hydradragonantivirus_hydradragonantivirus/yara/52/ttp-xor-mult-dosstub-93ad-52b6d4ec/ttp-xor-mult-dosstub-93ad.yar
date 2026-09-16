rule TTP_XOR_MULT_DOSStub_93ad {
  strings:
    $key_93ad = { c7 c5 [2] b3 dd [2] f4 df [2] b3 ce [2] fd c2 [2] f1 c8 [2] e6 c3 [2] fd 8d [2] c0 }

  condition:
    any of them
}