rule TTP_XOR_MULT_DOSStub_72b3 {
  strings:
    $key_72b3 = { 26 db [2] 52 c3 [2] 15 c1 [2] 52 d0 [2] 1c dc [2] 10 d6 [2] 07 dd [2] 1c 93 [2] 21 }

  condition:
    any of them
}