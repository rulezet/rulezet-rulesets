rule TTP_XOR_MULT_DOSStub_a80f {
  strings:
    $key_a80f = { fc 67 [2] 88 7f [2] cf 7d [2] 88 6c [2] c6 60 [2] ca 6a [2] dd 61 [2] c6 2f [2] fb }

  condition:
    any of them
}