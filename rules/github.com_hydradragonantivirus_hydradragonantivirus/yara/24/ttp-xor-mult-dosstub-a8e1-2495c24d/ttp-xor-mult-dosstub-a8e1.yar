rule TTP_XOR_MULT_DOSStub_a8e1 {
  strings:
    $key_a8e1 = { fc 89 [2] 88 91 [2] cf 93 [2] 88 82 [2] c6 8e [2] ca 84 [2] dd 8f [2] c6 c1 [2] fb }

  condition:
    any of them
}