rule TTP_XOR_MULT_DOSStub_11b8 {
  strings:
    $key_11b8 = { 45 d0 [2] 31 c8 [2] 76 ca [2] 31 db [2] 7f d7 [2] 73 dd [2] 64 d6 [2] 7f 98 [2] 42 }

  condition:
    any of them
}