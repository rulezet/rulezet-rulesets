rule TTP_XOR_MULT_DOSStub_ae24 {
  strings:
    $key_ae24 = { fa 4c [2] 8e 54 [2] c9 56 [2] 8e 47 [2] c0 4b [2] cc 41 [2] db 4a [2] c0 04 [2] fd }

  condition:
    any of them
}