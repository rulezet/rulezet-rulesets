rule TTP_XOR_MULT_DOSStub_fca4 {
  strings:
    $key_fca4 = { a8 cc [2] dc d4 [2] 9b d6 [2] dc c7 [2] 92 cb [2] 9e c1 [2] 89 ca [2] 92 84 [2] af }

  condition:
    any of them
}