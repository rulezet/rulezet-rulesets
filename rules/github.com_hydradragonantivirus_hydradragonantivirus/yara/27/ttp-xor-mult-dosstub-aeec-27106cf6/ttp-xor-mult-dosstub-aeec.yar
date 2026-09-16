rule TTP_XOR_MULT_DOSStub_aeec {
  strings:
    $key_aeec = { fa 84 [2] 8e 9c [2] c9 9e [2] 8e 8f [2] c0 83 [2] cc 89 [2] db 82 [2] c0 cc [2] fd }

  condition:
    any of them
}