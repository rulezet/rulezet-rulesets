rule TTP_XOR_MULT_DOSStub_fc43 {
  strings:
    $key_fc43 = { a8 2b [2] dc 33 [2] 9b 31 [2] dc 20 [2] 92 2c [2] 9e 26 [2] 89 2d [2] 92 63 [2] af }

  condition:
    any of them
}