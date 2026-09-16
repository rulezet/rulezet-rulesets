rule TTP_XOR_MULT_DOSStub_a8e8 {
  strings:
    $key_a8e8 = { fc 80 [2] 88 98 [2] cf 9a [2] 88 8b [2] c6 87 [2] ca 8d [2] dd 86 [2] c6 c8 [2] fb }

  condition:
    any of them
}