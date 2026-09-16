rule TTP_XOR_MULT_DOSStub_34b8 {
  strings:
    $key_34b8 = { 60 d0 [2] 14 c8 [2] 53 ca [2] 14 db [2] 5a d7 [2] 56 dd [2] 41 d6 [2] 5a 98 [2] 67 }

  condition:
    any of them
}