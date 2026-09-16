rule TTP_XOR_MULT_DOSStub_eaa4 {
  strings:
    $key_eaa4 = { be cc [2] ca d4 [2] 8d d6 [2] ca c7 [2] 84 cb [2] 88 c1 [2] 9f ca [2] 84 84 [2] b9 }

  condition:
    any of them
}