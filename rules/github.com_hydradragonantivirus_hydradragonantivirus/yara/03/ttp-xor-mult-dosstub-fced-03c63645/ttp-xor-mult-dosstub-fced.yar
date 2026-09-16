rule TTP_XOR_MULT_DOSStub_fced {
  strings:
    $key_fced = { a8 85 [2] dc 9d [2] 9b 9f [2] dc 8e [2] 92 82 [2] 9e 88 [2] 89 83 [2] 92 cd [2] af }

  condition:
    any of them
}