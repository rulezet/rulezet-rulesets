rule TTP_XOR_MULT_DOSStub_aef9 {
  strings:
    $key_aef9 = { fa 91 [2] 8e 89 [2] c9 8b [2] 8e 9a [2] c0 96 [2] cc 9c [2] db 97 [2] c0 d9 [2] fd }

  condition:
    any of them
}