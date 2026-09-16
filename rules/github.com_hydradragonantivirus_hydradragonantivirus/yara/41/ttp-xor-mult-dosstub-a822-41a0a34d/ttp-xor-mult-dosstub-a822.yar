rule TTP_XOR_MULT_DOSStub_a822 {
  strings:
    $key_a822 = { fc 4a [2] 88 52 [2] cf 50 [2] 88 41 [2] c6 4d [2] ca 47 [2] dd 4c [2] c6 02 [2] fb }

  condition:
    any of them
}