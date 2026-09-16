rule TTP_XOR_MULT_DOSStub_aee8 {
  strings:
    $key_aee8 = { fa 80 [2] 8e 98 [2] c9 9a [2] 8e 8b [2] c0 87 [2] cc 8d [2] db 86 [2] c0 c8 [2] fd }

  condition:
    any of them
}