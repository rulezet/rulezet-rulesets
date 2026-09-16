rule TTP_XOR_MULT_DOSStub_02b5 {
  strings:
    $key_02b5 = { 56 dd [2] 22 c5 [2] 65 c7 [2] 22 d6 [2] 6c da [2] 60 d0 [2] 77 db [2] 6c 95 [2] 51 }

  condition:
    any of them
}