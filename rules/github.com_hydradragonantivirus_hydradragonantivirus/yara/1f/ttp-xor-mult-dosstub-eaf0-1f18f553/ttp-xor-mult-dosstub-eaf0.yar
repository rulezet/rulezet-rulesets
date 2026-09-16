rule TTP_XOR_MULT_DOSStub_eaf0 {
  strings:
    $key_eaf0 = { be 98 [2] ca 80 [2] 8d 82 [2] ca 93 [2] 84 9f [2] 88 95 [2] 9f 9e [2] 84 d0 [2] b9 }

  condition:
    any of them
}