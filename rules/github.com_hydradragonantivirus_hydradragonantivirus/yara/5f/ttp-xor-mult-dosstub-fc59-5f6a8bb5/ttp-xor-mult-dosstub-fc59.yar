rule TTP_XOR_MULT_DOSStub_fc59 {
  strings:
    $key_fc59 = { a8 31 [2] dc 29 [2] 9b 2b [2] dc 3a [2] 92 36 [2] 9e 3c [2] 89 37 [2] 92 79 [2] af }

  condition:
    any of them
}