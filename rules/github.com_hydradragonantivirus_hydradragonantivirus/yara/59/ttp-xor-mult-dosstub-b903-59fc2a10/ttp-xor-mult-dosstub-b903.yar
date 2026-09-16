rule TTP_XOR_MULT_DOSStub_b903 {
  strings:
    $key_b903 = { ed 6b [2] 99 73 [2] de 71 [2] 99 60 [2] d7 6c [2] db 66 [2] cc 6d [2] d7 23 [2] ea }

  condition:
    any of them
}