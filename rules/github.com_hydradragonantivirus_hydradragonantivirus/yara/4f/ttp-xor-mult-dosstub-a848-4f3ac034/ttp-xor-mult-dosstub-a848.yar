rule TTP_XOR_MULT_DOSStub_a848 {
  strings:
    $key_a848 = { fc 20 [2] 88 38 [2] cf 3a [2] 88 2b [2] c6 27 [2] ca 2d [2] dd 26 [2] c6 68 [2] fb }

  condition:
    any of them
}