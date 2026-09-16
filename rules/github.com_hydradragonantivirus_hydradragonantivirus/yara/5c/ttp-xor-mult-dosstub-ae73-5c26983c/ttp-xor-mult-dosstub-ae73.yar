rule TTP_XOR_MULT_DOSStub_ae73 {
  strings:
    $key_ae73 = { fa 1b [2] 8e 03 [2] c9 01 [2] 8e 10 [2] c0 1c [2] cc 16 [2] db 1d [2] c0 53 [2] fd }

  condition:
    any of them
}