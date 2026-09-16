rule TTP_XOR_MULT_DOSStub_a842 {
  strings:
    $key_a842 = { fc 2a [2] 88 32 [2] cf 30 [2] 88 21 [2] c6 2d [2] ca 27 [2] dd 2c [2] c6 62 [2] fb }

  condition:
    any of them
}