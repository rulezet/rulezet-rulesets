rule TTP_XOR_MULT_DOSStub_eaba {
  strings:
    $key_eaba = { be d2 [2] ca ca [2] 8d c8 [2] ca d9 [2] 84 d5 [2] 88 df [2] 9f d4 [2] 84 9a [2] b9 }

  condition:
    any of them
}