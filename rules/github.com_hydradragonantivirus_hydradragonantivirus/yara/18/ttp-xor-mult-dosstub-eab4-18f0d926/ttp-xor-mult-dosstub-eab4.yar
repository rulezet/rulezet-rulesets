rule TTP_XOR_MULT_DOSStub_eab4 {
  strings:
    $key_eab4 = { be dc [2] ca c4 [2] 8d c6 [2] ca d7 [2] 84 db [2] 88 d1 [2] 9f da [2] 84 94 [2] b9 }

  condition:
    any of them
}