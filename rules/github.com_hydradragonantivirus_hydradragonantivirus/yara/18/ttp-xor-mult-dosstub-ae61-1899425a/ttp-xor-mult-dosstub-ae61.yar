rule TTP_XOR_MULT_DOSStub_ae61 {
  strings:
    $key_ae61 = { fa 09 [2] 8e 11 [2] c9 13 [2] 8e 02 [2] c0 0e [2] cc 04 [2] db 0f [2] c0 41 [2] fd }

  condition:
    any of them
}