rule TTP_XOR_MULT_DOSStub_fbb2 {
  strings:
    $key_fbb2 = { af da [2] db c2 [2] 9c c0 [2] db d1 [2] 95 dd [2] 99 d7 [2] 8e dc [2] 95 92 [2] a8 }

  condition:
    any of them
}