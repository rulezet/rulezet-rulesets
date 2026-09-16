rule TTP_XOR_MULT_DOSStub_eadd {
  strings:
    $key_eadd = { be b5 [2] ca ad [2] 8d af [2] ca be [2] 84 b2 [2] 88 b8 [2] 9f b3 [2] 84 fd [2] b9 }

  condition:
    any of them
}