rule TTP_XOR_MULT_DOSStub_f6ad {
  strings:
    $key_f6ad = { a2 c5 [2] d6 dd [2] 91 df [2] d6 ce [2] 98 c2 [2] 94 c8 [2] 83 c3 [2] 98 8d [2] a5 }

  condition:
    any of them
}