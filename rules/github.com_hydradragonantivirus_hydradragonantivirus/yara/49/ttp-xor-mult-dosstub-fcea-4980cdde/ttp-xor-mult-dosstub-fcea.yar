rule TTP_XOR_MULT_DOSStub_fcea {
  strings:
    $key_fcea = { a8 82 [2] dc 9a [2] 9b 98 [2] dc 89 [2] 92 85 [2] 9e 8f [2] 89 84 [2] 92 ca [2] af }

  condition:
    any of them
}