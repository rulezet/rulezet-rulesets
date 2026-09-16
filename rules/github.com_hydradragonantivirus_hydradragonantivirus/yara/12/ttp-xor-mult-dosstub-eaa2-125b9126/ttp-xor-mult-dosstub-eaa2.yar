rule TTP_XOR_MULT_DOSStub_eaa2 {
  strings:
    $key_eaa2 = { be ca [2] ca d2 [2] 8d d0 [2] ca c1 [2] 84 cd [2] 88 c7 [2] 9f cc [2] 84 82 [2] b9 }

  condition:
    any of them
}