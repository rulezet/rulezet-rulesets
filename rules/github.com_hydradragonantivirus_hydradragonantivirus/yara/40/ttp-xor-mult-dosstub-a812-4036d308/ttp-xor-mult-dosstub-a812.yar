rule TTP_XOR_MULT_DOSStub_a812 {
  strings:
    $key_a812 = { fc 7a [2] 88 62 [2] cf 60 [2] 88 71 [2] c6 7d [2] ca 77 [2] dd 7c [2] c6 32 [2] fb }

  condition:
    any of them
}