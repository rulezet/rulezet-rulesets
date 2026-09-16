rule TTP_XOR_MULT_DOSStub_fcaf {
  strings:
    $key_fcaf = { a8 c7 [2] dc df [2] 9b dd [2] dc cc [2] 92 c0 [2] 9e ca [2] 89 c1 [2] 92 8f [2] af }

  condition:
    any of them
}