rule TTP_XOR_MULT_DOSStub_fc2a {
  strings:
    $key_fc2a = { a8 42 [2] dc 5a [2] 9b 58 [2] dc 49 [2] 92 45 [2] 9e 4f [2] 89 44 [2] 92 0a [2] af }

  condition:
    any of them
}