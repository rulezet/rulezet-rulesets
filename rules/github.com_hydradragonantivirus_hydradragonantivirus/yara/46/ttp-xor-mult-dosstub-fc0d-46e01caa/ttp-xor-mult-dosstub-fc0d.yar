rule TTP_XOR_MULT_DOSStub_fc0d {
  strings:
    $key_fc0d = { a8 65 [2] dc 7d [2] 9b 7f [2] dc 6e [2] 92 62 [2] 9e 68 [2] 89 63 [2] 92 2d [2] af }

  condition:
    any of them
}