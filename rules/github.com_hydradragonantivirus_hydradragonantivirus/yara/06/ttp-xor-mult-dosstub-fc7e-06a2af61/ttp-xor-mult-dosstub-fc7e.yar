rule TTP_XOR_MULT_DOSStub_fc7e {
  strings:
    $key_fc7e = { a8 16 [2] dc 0e [2] 9b 0c [2] dc 1d [2] 92 11 [2] 9e 1b [2] 89 10 [2] 92 5e [2] af }

  condition:
    any of them
}