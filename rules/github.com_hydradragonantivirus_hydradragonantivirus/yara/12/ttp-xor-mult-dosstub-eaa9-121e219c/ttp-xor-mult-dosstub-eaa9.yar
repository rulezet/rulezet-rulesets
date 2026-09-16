rule TTP_XOR_MULT_DOSStub_eaa9 {
  strings:
    $key_eaa9 = { be c1 [2] ca d9 [2] 8d db [2] ca ca [2] 84 c6 [2] 88 cc [2] 9f c7 [2] 84 89 [2] b9 }

  condition:
    any of them
}