rule TTP_XOR_MULT_DOSStub_fc4f {
  strings:
    $key_fc4f = { a8 27 [2] dc 3f [2] 9b 3d [2] dc 2c [2] 92 20 [2] 9e 2a [2] 89 21 [2] 92 6f [2] af }

  condition:
    any of them
}