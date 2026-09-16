rule TTP_XOR_MULT_DOSStub_fc53 {
  strings:
    $key_fc53 = { a8 3b [2] dc 23 [2] 9b 21 [2] dc 30 [2] 92 3c [2] 9e 36 [2] 89 3d [2] 92 73 [2] af }

  condition:
    any of them
}