rule TTP_XOR_MULT_DOSStub_fc0a {
  strings:
    $key_fc0a = { a8 62 [2] dc 7a [2] 9b 78 [2] dc 69 [2] 92 65 [2] 9e 6f [2] 89 64 [2] 92 2a [2] af }

  condition:
    any of them
}