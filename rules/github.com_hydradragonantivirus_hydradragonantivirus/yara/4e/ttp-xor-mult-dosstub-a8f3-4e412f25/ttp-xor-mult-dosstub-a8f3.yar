rule TTP_XOR_MULT_DOSStub_a8f3 {
  strings:
    $key_a8f3 = { fc 9b [2] 88 83 [2] cf 81 [2] 88 90 [2] c6 9c [2] ca 96 [2] dd 9d [2] c6 d3 [2] fb }

  condition:
    any of them
}