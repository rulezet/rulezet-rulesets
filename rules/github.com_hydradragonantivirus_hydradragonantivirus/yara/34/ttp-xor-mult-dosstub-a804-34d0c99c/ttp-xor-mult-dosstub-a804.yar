rule TTP_XOR_MULT_DOSStub_a804 {
  strings:
    $key_a804 = { fc 6c [2] 88 74 [2] cf 76 [2] 88 67 [2] c6 6b [2] ca 61 [2] dd 6a [2] c6 24 [2] fb }

  condition:
    any of them
}