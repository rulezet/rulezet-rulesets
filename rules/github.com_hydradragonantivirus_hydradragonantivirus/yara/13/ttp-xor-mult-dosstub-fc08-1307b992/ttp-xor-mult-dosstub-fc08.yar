rule TTP_XOR_MULT_DOSStub_fc08 {
  strings:
    $key_fc08 = { a8 60 [2] dc 78 [2] 9b 7a [2] dc 6b [2] 92 67 [2] 9e 6d [2] 89 66 [2] 92 28 [2] af }

  condition:
    any of them
}