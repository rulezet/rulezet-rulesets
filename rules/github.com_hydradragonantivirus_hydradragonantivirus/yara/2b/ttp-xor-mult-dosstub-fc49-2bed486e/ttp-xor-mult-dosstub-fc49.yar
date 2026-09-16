rule TTP_XOR_MULT_DOSStub_fc49 {
  strings:
    $key_fc49 = { a8 21 [2] dc 39 [2] 9b 3b [2] dc 2a [2] 92 26 [2] 9e 2c [2] 89 27 [2] 92 69 [2] af }

  condition:
    any of them
}