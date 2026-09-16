rule TTP_XOR_MULT_DOSStub_b91d {
  strings:
    $key_b91d = { ed 75 [2] 99 6d [2] de 6f [2] 99 7e [2] d7 72 [2] db 78 [2] cc 73 [2] d7 3d [2] ea }

  condition:
    any of them
}