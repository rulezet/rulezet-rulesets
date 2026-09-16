rule TTP_XOR_MULT_DOSStub_fcae {
  strings:
    $key_fcae = { a8 c6 [2] dc de [2] 9b dc [2] dc cd [2] 92 c1 [2] 9e cb [2] 89 c0 [2] 92 8e [2] af }

  condition:
    any of them
}