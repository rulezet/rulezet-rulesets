rule TTP_XOR_MULT_DOSStub_efeb {
  strings:
    $key_efeb = { bb 83 [2] cf 9b [2] 88 99 [2] cf 88 [2] 81 84 [2] 8d 8e [2] 9a 85 [2] 81 cb [2] bc }

  condition:
    any of them
}