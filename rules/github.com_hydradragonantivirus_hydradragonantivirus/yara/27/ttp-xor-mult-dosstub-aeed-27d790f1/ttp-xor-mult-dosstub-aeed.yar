rule TTP_XOR_MULT_DOSStub_aeed {
  strings:
    $key_aeed = { fa 85 [2] 8e 9d [2] c9 9f [2] 8e 8e [2] c0 82 [2] cc 88 [2] db 83 [2] c0 cd [2] fd }

  condition:
    any of them
}