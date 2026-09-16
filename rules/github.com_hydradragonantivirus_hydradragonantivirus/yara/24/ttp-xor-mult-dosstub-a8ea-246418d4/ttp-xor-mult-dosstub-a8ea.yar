rule TTP_XOR_MULT_DOSStub_a8ea {
  strings:
    $key_a8ea = { fc 82 [2] 88 9a [2] cf 98 [2] 88 89 [2] c6 85 [2] ca 8f [2] dd 84 [2] c6 ca [2] fb }

  condition:
    any of them
}