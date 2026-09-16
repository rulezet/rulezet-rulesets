rule TTP_XOR_MULT_DOSStub_fc4d {
  strings:
    $key_fc4d = { a8 25 [2] dc 3d [2] 9b 3f [2] dc 2e [2] 92 22 [2] 9e 28 [2] 89 23 [2] 92 6d [2] af }

  condition:
    any of them
}