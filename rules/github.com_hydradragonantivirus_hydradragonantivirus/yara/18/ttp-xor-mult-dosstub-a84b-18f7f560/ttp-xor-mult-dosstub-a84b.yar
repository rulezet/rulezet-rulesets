rule TTP_XOR_MULT_DOSStub_a84b {
  strings:
    $key_a84b = { fc 23 [2] 88 3b [2] cf 39 [2] 88 28 [2] c6 24 [2] ca 2e [2] dd 25 [2] c6 6b [2] fb }

  condition:
    any of them
}