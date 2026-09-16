rule TTP_XOR_MULT_DOSStub_b9fd {
  strings:
    $key_b9fd = { ed 95 [2] 99 8d [2] de 8f [2] 99 9e [2] d7 92 [2] db 98 [2] cc 93 [2] d7 dd [2] ea }

  condition:
    any of them
}