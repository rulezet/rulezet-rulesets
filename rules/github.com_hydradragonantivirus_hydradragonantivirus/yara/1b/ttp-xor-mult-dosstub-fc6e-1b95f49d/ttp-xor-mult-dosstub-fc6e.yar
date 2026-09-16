rule TTP_XOR_MULT_DOSStub_fc6e {
  strings:
    $key_fc6e = { a8 06 [2] dc 1e [2] 9b 1c [2] dc 0d [2] 92 01 [2] 9e 0b [2] 89 00 [2] 92 4e [2] af }

  condition:
    any of them
}