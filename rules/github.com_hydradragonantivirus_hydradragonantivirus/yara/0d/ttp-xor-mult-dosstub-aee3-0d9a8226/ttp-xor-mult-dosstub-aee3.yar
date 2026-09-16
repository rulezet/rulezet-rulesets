rule TTP_XOR_MULT_DOSStub_aee3 {
  strings:
    $key_aee3 = { fa 8b [2] 8e 93 [2] c9 91 [2] 8e 80 [2] c0 8c [2] cc 86 [2] db 8d [2] c0 c3 [2] fd }

  condition:
    any of them
}