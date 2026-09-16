rule TTP_XOR_MULT_DOSStub_fc1d {
  strings:
    $key_fc1d = { a8 75 [2] dc 6d [2] 9b 6f [2] dc 7e [2] 92 72 [2] 9e 78 [2] 89 73 [2] 92 3d [2] af }

  condition:
    any of them
}