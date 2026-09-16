rule TTP_XOR_MULT_DOSStub_afba {
  strings:
    $key_afba = { fb d2 [2] 8f ca [2] c8 c8 [2] 8f d9 [2] c1 d5 [2] cd df [2] da d4 [2] c1 9a [2] fc }

  condition:
    any of them
}