rule TTP_XOR_MULT_DOSStub_eeeb {
  strings:
    $key_eeeb = { ba 83 [2] ce 9b [2] 89 99 [2] ce 88 [2] 80 84 [2] 8c 8e [2] 9b 85 [2] 80 cb [2] bd }

  condition:
    any of them
}