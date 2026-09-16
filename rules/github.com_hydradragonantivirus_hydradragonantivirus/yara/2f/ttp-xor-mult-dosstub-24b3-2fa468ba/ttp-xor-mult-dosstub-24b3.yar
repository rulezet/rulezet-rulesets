rule TTP_XOR_MULT_DOSStub_24b3 {
  strings:
    $key_24b3 = { 70 db [2] 04 c3 [2] 43 c1 [2] 04 d0 [2] 4a dc [2] 46 d6 [2] 51 dd [2] 4a 93 [2] 77 }

  condition:
    any of them
}