rule TTP_XOR_MULT_DOSStub_a8f6 {
  strings:
    $key_a8f6 = { fc 9e [2] 88 86 [2] cf 84 [2] 88 95 [2] c6 99 [2] ca 93 [2] dd 98 [2] c6 d6 [2] fb }

  condition:
    any of them
}