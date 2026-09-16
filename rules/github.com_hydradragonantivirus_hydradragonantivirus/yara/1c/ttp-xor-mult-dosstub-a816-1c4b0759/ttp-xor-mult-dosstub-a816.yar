rule TTP_XOR_MULT_DOSStub_a816 {
  strings:
    $key_a816 = { fc 7e [2] 88 66 [2] cf 64 [2] 88 75 [2] c6 79 [2] ca 73 [2] dd 78 [2] c6 36 [2] fb }

  condition:
    any of them
}