rule TTP_XOR_MULT_DOSStub_eaf6 {
  strings:
    $key_eaf6 = { be 9e [2] ca 86 [2] 8d 84 [2] ca 95 [2] 84 99 [2] 88 93 [2] 9f 98 [2] 84 d6 [2] b9 }

  condition:
    any of them
}