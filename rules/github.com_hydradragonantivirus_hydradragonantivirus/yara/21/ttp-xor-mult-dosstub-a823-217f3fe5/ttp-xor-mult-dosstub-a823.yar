rule TTP_XOR_MULT_DOSStub_a823 {
  strings:
    $key_a823 = { fc 4b [2] 88 53 [2] cf 51 [2] 88 40 [2] c6 4c [2] ca 46 [2] dd 4d [2] c6 03 [2] fb }

  condition:
    any of them
}