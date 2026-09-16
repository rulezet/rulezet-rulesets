rule TTP_XOR_MULT_DOSStub_a875 {
  strings:
    $key_a875 = { fc 1d [2] 88 05 [2] cf 07 [2] 88 16 [2] c6 1a [2] ca 10 [2] dd 1b [2] c6 55 [2] fb }

  condition:
    any of them
}