rule TTP_XOR_MULT_DOSStub_c5be {
  strings:
    $key_c5be = { 91 d6 [2] e5 ce [2] a2 cc [2] e5 dd [2] ab d1 [2] a7 db [2] b0 d0 [2] ab 9e [2] 96 }

  condition:
    any of them
}