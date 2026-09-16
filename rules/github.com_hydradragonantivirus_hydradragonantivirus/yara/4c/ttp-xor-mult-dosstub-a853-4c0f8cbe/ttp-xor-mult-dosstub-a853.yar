rule TTP_XOR_MULT_DOSStub_a853 {
  strings:
    $key_a853 = { fc 3b [2] 88 23 [2] cf 21 [2] 88 30 [2] c6 3c [2] ca 36 [2] dd 3d [2] c6 73 [2] fb }

  condition:
    any of them
}