rule TTP_XOR_MULT_DOSStub_aeeb {
  strings:
    $key_aeeb = { fa 83 [2] 8e 9b [2] c9 99 [2] 8e 88 [2] c0 84 [2] cc 8e [2] db 85 [2] c0 cb [2] fd }

  condition:
    any of them
}