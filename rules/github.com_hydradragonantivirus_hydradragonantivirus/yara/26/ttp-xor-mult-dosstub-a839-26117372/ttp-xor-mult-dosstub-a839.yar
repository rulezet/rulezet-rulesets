rule TTP_XOR_MULT_DOSStub_a839 {
  strings:
    $key_a839 = { fc 51 [2] 88 49 [2] cf 4b [2] 88 5a [2] c6 56 [2] ca 5c [2] dd 57 [2] c6 19 [2] fb }

  condition:
    any of them
}