rule TTP_XOR_MULT_DOSStub_72b5 {
  strings:
    $key_72b5 = { 26 dd [2] 52 c5 [2] 15 c7 [2] 52 d6 [2] 1c da [2] 10 d0 [2] 07 db [2] 1c 95 [2] 21 }

  condition:
    any of them
}