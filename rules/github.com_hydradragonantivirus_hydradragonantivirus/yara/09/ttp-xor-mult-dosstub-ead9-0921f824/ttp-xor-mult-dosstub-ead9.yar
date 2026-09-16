rule TTP_XOR_MULT_DOSStub_ead9 {
  strings:
    $key_ead9 = { be b1 [2] ca a9 [2] 8d ab [2] ca ba [2] 84 b6 [2] 88 bc [2] 9f b7 [2] 84 f9 [2] b9 }

  condition:
    any of them
}