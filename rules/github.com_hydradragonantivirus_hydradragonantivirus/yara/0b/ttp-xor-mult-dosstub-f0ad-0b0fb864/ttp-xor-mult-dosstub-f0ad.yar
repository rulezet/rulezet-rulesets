rule TTP_XOR_MULT_DOSStub_f0ad {
  strings:
    $key_f0ad = { a4 c5 [2] d0 dd [2] 97 df [2] d0 ce [2] 9e c2 [2] 92 c8 [2] 85 c3 [2] 9e 8d [2] a3 }

  condition:
    any of them
}