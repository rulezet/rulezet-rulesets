rule TTP_XOR_MULT_DOSStub_a809 {
  strings:
    $key_a809 = { fc 61 [2] 88 79 [2] cf 7b [2] 88 6a [2] c6 66 [2] ca 6c [2] dd 67 [2] c6 29 [2] fb }

  condition:
    any of them
}