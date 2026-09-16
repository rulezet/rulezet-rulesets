rule TTP_XOR_MULT_DOSStub_b96d {
  strings:
    $key_b96d = { ed 05 [2] 99 1d [2] de 1f [2] 99 0e [2] d7 02 [2] db 08 [2] cc 03 [2] d7 4d [2] ea }

  condition:
    any of them
}