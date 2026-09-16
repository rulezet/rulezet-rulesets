rule TTP_XOR_MULT_DOSStub_eaa5 {
  strings:
    $key_eaa5 = { be cd [2] ca d5 [2] 8d d7 [2] ca c6 [2] 84 ca [2] 88 c0 [2] 9f cb [2] 84 85 [2] b9 }

  condition:
    any of them
}