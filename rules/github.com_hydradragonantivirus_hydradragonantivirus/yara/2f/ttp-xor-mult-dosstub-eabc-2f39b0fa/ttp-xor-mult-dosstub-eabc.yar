rule TTP_XOR_MULT_DOSStub_eabc {
  strings:
    $key_eabc = { be d4 [2] ca cc [2] 8d ce [2] ca df [2] 84 d3 [2] 88 d9 [2] 9f d2 [2] 84 9c [2] b9 }

  condition:
    any of them
}