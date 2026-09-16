rule TTP_XOR_MULT_DOSStub_a8f1 {
  strings:
    $key_a8f1 = { fc 99 [2] 88 81 [2] cf 83 [2] 88 92 [2] c6 9e [2] ca 94 [2] dd 9f [2] c6 d1 [2] fb }

  condition:
    any of them
}