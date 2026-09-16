rule TTP_XOR_MULT_DOSStub_eeae {
  strings:
    $key_eeae = { ba c6 [2] ce de [2] 89 dc [2] ce cd [2] 80 c1 [2] 8c cb [2] 9b c0 [2] 80 8e [2] bd }

  condition:
    any of them
}