rule TTP_XOR_MULT_DOSStub_fc0f {
  strings:
    $key_fc0f = { a8 67 [2] dc 7f [2] 9b 7d [2] dc 6c [2] 92 60 [2] 9e 6a [2] 89 61 [2] 92 2f [2] af }

  condition:
    any of them
}