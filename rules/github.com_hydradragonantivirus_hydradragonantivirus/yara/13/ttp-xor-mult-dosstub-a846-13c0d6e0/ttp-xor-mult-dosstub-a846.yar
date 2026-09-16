rule TTP_XOR_MULT_DOSStub_a846 {
  strings:
    $key_a846 = { fc 2e [2] 88 36 [2] cf 34 [2] 88 25 [2] c6 29 [2] ca 23 [2] dd 28 [2] c6 66 [2] fb }

  condition:
    any of them
}