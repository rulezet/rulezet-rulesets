rule TTP_XOR_MULT_DOSStub_feeb {
  strings:
    $key_feeb = { aa 83 [2] de 9b [2] 99 99 [2] de 88 [2] 90 84 [2] 9c 8e [2] 8b 85 [2] 90 cb [2] ad }

  condition:
    any of them
}