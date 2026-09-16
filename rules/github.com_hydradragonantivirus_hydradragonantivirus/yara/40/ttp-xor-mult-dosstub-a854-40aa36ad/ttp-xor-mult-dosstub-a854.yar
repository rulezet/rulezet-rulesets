rule TTP_XOR_MULT_DOSStub_a854 {
  strings:
    $key_a854 = { fc 3c [2] 88 24 [2] cf 26 [2] 88 37 [2] c6 3b [2] ca 31 [2] dd 3a [2] c6 74 [2] fb }

  condition:
    any of them
}