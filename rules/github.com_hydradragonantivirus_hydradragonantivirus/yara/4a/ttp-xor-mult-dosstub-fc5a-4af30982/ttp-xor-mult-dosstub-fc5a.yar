rule TTP_XOR_MULT_DOSStub_fc5a {
  strings:
    $key_fc5a = { a8 32 [2] dc 2a [2] 9b 28 [2] dc 39 [2] 92 35 [2] 9e 3f [2] 89 34 [2] 92 7a [2] af }

  condition:
    any of them
}