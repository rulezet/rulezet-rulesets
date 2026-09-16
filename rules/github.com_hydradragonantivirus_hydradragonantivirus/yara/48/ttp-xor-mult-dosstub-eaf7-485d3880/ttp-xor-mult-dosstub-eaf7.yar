rule TTP_XOR_MULT_DOSStub_eaf7 {
  strings:
    $key_eaf7 = { be 9f [2] ca 87 [2] 8d 85 [2] ca 94 [2] 84 98 [2] 88 92 [2] 9f 99 [2] 84 d7 [2] b9 }

  condition:
    any of them
}