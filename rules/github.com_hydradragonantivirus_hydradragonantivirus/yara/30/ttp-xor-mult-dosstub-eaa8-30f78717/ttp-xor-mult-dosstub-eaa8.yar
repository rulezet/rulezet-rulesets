rule TTP_XOR_MULT_DOSStub_eaa8 {
  strings:
    $key_eaa8 = { be c0 [2] ca d8 [2] 8d da [2] ca cb [2] 84 c7 [2] 88 cd [2] 9f c6 [2] 84 88 [2] b9 }

  condition:
    any of them
}