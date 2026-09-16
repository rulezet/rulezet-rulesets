rule TTP_XOR_MULT_DOSStub_a81e {
  strings:
    $key_a81e = { fc 76 [2] 88 6e [2] cf 6c [2] 88 7d [2] c6 71 [2] ca 7b [2] dd 70 [2] c6 3e [2] fb }

  condition:
    any of them
}