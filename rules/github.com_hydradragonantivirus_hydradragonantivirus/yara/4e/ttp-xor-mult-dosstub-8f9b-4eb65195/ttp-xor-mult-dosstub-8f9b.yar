rule TTP_XOR_MULT_DOSStub_8f9b {
  strings:
    $key_8f9b = { db f3 [2] af eb [2] e8 e9 [2] af f8 [2] e1 f4 [2] ed fe [2] fa f5 [2] e1 bb [2] dc }

  condition:
    any of them
}