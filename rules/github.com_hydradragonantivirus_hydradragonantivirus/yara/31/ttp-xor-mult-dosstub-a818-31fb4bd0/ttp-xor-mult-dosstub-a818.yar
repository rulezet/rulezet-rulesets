rule TTP_XOR_MULT_DOSStub_a818 {
  strings:
    $key_a818 = { fc 70 [2] 88 68 [2] cf 6a [2] 88 7b [2] c6 77 [2] ca 7d [2] dd 76 [2] c6 38 [2] fb }

  condition:
    any of them
}