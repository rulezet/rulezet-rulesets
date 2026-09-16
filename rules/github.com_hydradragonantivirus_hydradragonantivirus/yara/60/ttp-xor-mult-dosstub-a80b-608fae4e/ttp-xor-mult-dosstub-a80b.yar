rule TTP_XOR_MULT_DOSStub_a80b {
  strings:
    $key_a80b = { fc 63 [2] 88 7b [2] cf 79 [2] 88 68 [2] c6 64 [2] ca 6e [2] dd 65 [2] c6 2b [2] fb }

  condition:
    any of them
}