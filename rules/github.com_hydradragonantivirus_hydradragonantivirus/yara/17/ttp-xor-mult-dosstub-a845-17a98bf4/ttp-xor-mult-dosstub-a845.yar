rule TTP_XOR_MULT_DOSStub_a845 {
  strings:
    $key_a845 = { fc 2d [2] 88 35 [2] cf 37 [2] 88 26 [2] c6 2a [2] ca 20 [2] dd 2b [2] c6 65 [2] fb }

  condition:
    any of them
}