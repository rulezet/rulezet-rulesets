rule TTP_XOR_MULT_DOSStub_fc13 {
  strings:
    $key_fc13 = { a8 7b [2] dc 63 [2] 9b 61 [2] dc 70 [2] 92 7c [2] 9e 76 [2] 89 7d [2] 92 33 [2] af }

  condition:
    any of them
}