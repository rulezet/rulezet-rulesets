rule TTP_XOR_MULT_DOSStub_a803 {
  strings:
    $key_a803 = { fc 6b [2] 88 73 [2] cf 71 [2] 88 60 [2] c6 6c [2] ca 66 [2] dd 6d [2] c6 23 [2] fb }

  condition:
    any of them
}