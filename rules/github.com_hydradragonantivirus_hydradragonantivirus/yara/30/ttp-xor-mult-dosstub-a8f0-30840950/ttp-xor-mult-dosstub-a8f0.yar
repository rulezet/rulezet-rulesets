rule TTP_XOR_MULT_DOSStub_a8f0 {
  strings:
    $key_a8f0 = { fc 98 [2] 88 80 [2] cf 82 [2] 88 93 [2] c6 9f [2] ca 95 [2] dd 9e [2] c6 d0 [2] fb }

  condition:
    any of them
}