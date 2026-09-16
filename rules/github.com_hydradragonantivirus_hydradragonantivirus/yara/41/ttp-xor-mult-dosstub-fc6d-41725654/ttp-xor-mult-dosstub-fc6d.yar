rule TTP_XOR_MULT_DOSStub_fc6d {
  strings:
    $key_fc6d = { a8 05 [2] dc 1d [2] 9b 1f [2] dc 0e [2] 92 02 [2] 9e 08 [2] 89 03 [2] 92 4d [2] af }

  condition:
    any of them
}