rule TTP_XOR_MULT_DOSStub_a861 {
  strings:
    $key_a861 = { fc 09 [2] 88 11 [2] cf 13 [2] 88 02 [2] c6 0e [2] ca 04 [2] dd 0f [2] c6 41 [2] fb }

  condition:
    any of them
}