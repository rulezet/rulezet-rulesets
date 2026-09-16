rule TTP_XOR_MULT_DOSStub_a819 {
  strings:
    $key_a819 = { fc 71 [2] 88 69 [2] cf 6b [2] 88 7a [2] c6 76 [2] ca 7c [2] dd 77 [2] c6 39 [2] fb }

  condition:
    any of them
}