rule TTP_XOR_MULT_DOSStub_50b3 {
  strings:
    $key_50b3 = { 04 db [2] 70 c3 [2] 37 c1 [2] 70 d0 [2] 3e dc [2] 32 d6 [2] 25 dd [2] 3e 93 [2] 03 }

  condition:
    any of them
}