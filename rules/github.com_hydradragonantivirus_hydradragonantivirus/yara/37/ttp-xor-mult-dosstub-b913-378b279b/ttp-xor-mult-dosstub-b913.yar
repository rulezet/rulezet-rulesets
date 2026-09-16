rule TTP_XOR_MULT_DOSStub_b913 {
  strings:
    $key_b913 = { ed 7b [2] 99 63 [2] de 61 [2] 99 70 [2] d7 7c [2] db 76 [2] cc 7d [2] d7 33 [2] ea }

  condition:
    any of them
}