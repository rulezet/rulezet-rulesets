rule TTP_XOR_MULT_DOSStub_ae79 {
  strings:
    $key_ae79 = { fa 11 [2] 8e 09 [2] c9 0b [2] 8e 1a [2] c0 16 [2] cc 1c [2] db 17 [2] c0 59 [2] fd }

  condition:
    any of them
}