rule TTP_XOR_MULT_DOSStub_a8e9 {
  strings:
    $key_a8e9 = { fc 81 [2] 88 99 [2] cf 9b [2] 88 8a [2] c6 86 [2] ca 8c [2] dd 87 [2] c6 c9 [2] fb }

  condition:
    any of them
}