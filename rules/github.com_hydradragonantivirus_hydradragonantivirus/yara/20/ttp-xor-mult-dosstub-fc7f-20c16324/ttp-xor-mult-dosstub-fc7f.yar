rule TTP_XOR_MULT_DOSStub_fc7f {
  strings:
    $key_fc7f = { a8 17 [2] dc 0f [2] 9b 0d [2] dc 1c [2] 92 10 [2] 9e 1a [2] 89 11 [2] 92 5f [2] af }

  condition:
    any of them
}