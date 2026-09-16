rule TTP_XOR_MULT_DOSStub_b967 {
  strings:
    $key_b967 = { ed 0f [2] 99 17 [2] de 15 [2] 99 04 [2] d7 08 [2] db 02 [2] cc 09 [2] d7 47 [2] ea }

  condition:
    any of them
}