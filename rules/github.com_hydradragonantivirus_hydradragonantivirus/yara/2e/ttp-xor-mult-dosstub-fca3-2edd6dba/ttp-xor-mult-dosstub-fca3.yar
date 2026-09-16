rule TTP_XOR_MULT_DOSStub_fca3 {
  strings:
    $key_fca3 = { a8 cb [2] dc d3 [2] 9b d1 [2] dc c0 [2] 92 cc [2] 9e c6 [2] 89 cd [2] 92 83 [2] af }

  condition:
    any of them
}