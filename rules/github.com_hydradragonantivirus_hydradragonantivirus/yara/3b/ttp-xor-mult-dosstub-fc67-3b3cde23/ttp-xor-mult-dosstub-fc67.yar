rule TTP_XOR_MULT_DOSStub_fc67 {
  strings:
    $key_fc67 = { a8 0f [2] dc 17 [2] 9b 15 [2] dc 04 [2] 92 08 [2] 9e 02 [2] 89 09 [2] 92 47 [2] af }

  condition:
    any of them
}