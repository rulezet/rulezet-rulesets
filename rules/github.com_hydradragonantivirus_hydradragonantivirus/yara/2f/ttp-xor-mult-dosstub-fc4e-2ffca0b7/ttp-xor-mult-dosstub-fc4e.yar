rule TTP_XOR_MULT_DOSStub_fc4e {
  strings:
    $key_fc4e = { a8 26 [2] dc 3e [2] 9b 3c [2] dc 2d [2] 92 21 [2] 9e 2b [2] 89 20 [2] 92 6e [2] af }

  condition:
    any of them
}