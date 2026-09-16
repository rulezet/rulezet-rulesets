rule TTP_XOR_MULT_DOSStub_aeea {
  strings:
    $key_aeea = { fa 82 [2] 8e 9a [2] c9 98 [2] 8e 89 [2] c0 85 [2] cc 8f [2] db 84 [2] c0 ca [2] fd }

  condition:
    any of them
}