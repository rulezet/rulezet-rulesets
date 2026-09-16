rule TTP_XOR_MULT_DOSStub_fceb {
  strings:
    $key_fceb = { a8 83 [2] dc 9b [2] 9b 99 [2] dc 88 [2] 92 84 [2] 9e 8e [2] 89 85 [2] 92 cb [2] af }

  condition:
    any of them
}