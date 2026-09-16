rule TTP_XOR_MULT_DOSStub_fc58 {
  strings:
    $key_fc58 = { a8 30 [2] dc 28 [2] 9b 2a [2] dc 3b [2] 92 37 [2] 9e 3d [2] 89 36 [2] 92 78 [2] af }

  condition:
    any of them
}