rule TTP_XOR_MULT_DOSStub_fc3d {
  strings:
    $key_fc3d = { a8 55 [2] dc 4d [2] 9b 4f [2] dc 5e [2] 92 52 [2] 9e 58 [2] 89 53 [2] 92 1d [2] af }

  condition:
    any of them
}