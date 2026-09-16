rule TTP_XOR_MULT_DOSStub_eead {
  strings:
    $key_eead = { ba c5 [2] ce dd [2] 89 df [2] ce ce [2] 80 c2 [2] 8c c8 [2] 9b c3 [2] 80 8d [2] bd }

  condition:
    any of them
}