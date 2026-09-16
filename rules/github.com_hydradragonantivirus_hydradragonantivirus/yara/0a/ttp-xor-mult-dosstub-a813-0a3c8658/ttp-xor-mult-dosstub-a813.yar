rule TTP_XOR_MULT_DOSStub_a813 {
  strings:
    $key_a813 = { fc 7b [2] 88 63 [2] cf 61 [2] 88 70 [2] c6 7c [2] ca 76 [2] dd 7d [2] c6 33 [2] fb }

  condition:
    any of them
}