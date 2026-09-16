rule TTP_XOR_MULT_DOSStub_f2ad {
  strings:
    $key_f2ad = { a6 c5 [2] d2 dd [2] 95 df [2] d2 ce [2] 9c c2 [2] 90 c8 [2] 87 c3 [2] 9c 8d [2] a1 }

  condition:
    any of them
}