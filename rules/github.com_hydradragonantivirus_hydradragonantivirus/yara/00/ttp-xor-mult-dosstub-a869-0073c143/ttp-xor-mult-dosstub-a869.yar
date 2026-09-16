rule TTP_XOR_MULT_DOSStub_a869 {
  strings:
    $key_a869 = { fc 01 [2] 88 19 [2] cf 1b [2] 88 0a [2] c6 06 [2] ca 0c [2] dd 07 [2] c6 49 [2] fb }

  condition:
    any of them
}