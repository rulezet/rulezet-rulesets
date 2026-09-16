rule TTP_XOR_MULT_DOSStub_aee0 {
  strings:
    $key_aee0 = { fa 88 [2] 8e 90 [2] c9 92 [2] 8e 83 [2] c0 8f [2] cc 85 [2] db 8e [2] c0 c0 [2] fd }

  condition:
    any of them
}