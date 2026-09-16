rule TTP_XOR_MULT_DOSStub_70af {
  strings:
    $key_70af = { 24 c7 [2] 50 df [2] 17 dd [2] 50 cc [2] 1e c0 [2] 12 ca [2] 05 c1 [2] 1e 8f [2] 23 }

  condition:
    any of them
}