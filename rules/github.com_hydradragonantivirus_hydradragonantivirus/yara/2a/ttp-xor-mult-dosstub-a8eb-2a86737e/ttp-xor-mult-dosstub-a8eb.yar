rule TTP_XOR_MULT_DOSStub_a8eb {
  strings:
    $key_a8eb = { fc 83 [2] 88 9b [2] cf 99 [2] 88 88 [2] c6 84 [2] ca 8e [2] dd 85 [2] c6 cb [2] fb }

  condition:
    any of them
}