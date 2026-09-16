rule TTP_XOR_MULT_DOSStub_fc35 {
  strings:
    $key_fc35 = { a8 5d [2] dc 45 [2] 9b 47 [2] dc 56 [2] 92 5a [2] 9e 50 [2] 89 5b [2] 92 15 [2] af }

  condition:
    any of them
}