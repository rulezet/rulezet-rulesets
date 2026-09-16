rule TTP_XOR_MULT_DOSStub_a872 {
  strings:
    $key_a872 = { fc 1a [2] 88 02 [2] cf 00 [2] 88 11 [2] c6 1d [2] ca 17 [2] dd 1c [2] c6 52 [2] fb }

  condition:
    any of them
}