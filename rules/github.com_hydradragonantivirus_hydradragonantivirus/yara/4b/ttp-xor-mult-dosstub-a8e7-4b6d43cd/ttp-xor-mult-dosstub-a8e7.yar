rule TTP_XOR_MULT_DOSStub_a8e7 {
  strings:
    $key_a8e7 = { fc 8f [2] 88 97 [2] cf 95 [2] 88 84 [2] c6 88 [2] ca 82 [2] dd 89 [2] c6 c7 [2] fb }

  condition:
    any of them
}