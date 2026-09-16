rule TTP_XOR_MULT_DOSStub_fc6c {
  strings:
    $key_fc6c = { a8 04 [2] dc 1c [2] 9b 1e [2] dc 0f [2] 92 03 [2] 9e 09 [2] 89 02 [2] 92 4c [2] af }

  condition:
    any of them
}