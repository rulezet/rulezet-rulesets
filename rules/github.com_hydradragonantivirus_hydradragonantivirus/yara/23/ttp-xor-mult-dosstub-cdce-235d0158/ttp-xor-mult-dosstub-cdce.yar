rule TTP_XOR_MULT_DOSStub_cdce {
  strings:
    $key_cdce = { 99 a6 [2] ed be [2] aa bc [2] ed ad [2] a3 a1 [2] af ab [2] b8 a0 [2] a3 ee [2] 9e }

  condition:
    any of them
}