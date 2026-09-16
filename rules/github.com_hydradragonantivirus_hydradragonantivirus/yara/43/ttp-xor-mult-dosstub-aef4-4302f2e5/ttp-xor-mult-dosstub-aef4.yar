rule TTP_XOR_MULT_DOSStub_aef4 {
  strings:
    $key_aef4 = { fa 9c [2] 8e 84 [2] c9 86 [2] 8e 97 [2] c0 9b [2] cc 91 [2] db 9a [2] c0 d4 [2] fd }

  condition:
    any of them
}