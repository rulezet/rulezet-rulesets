rule TTP_XOR_MULT_DOSStub_a868 {
  strings:
    $key_a868 = { fc 00 [2] 88 18 [2] cf 1a [2] 88 0b [2] c6 07 [2] ca 0d [2] dd 06 [2] c6 48 [2] fb }

  condition:
    any of them
}