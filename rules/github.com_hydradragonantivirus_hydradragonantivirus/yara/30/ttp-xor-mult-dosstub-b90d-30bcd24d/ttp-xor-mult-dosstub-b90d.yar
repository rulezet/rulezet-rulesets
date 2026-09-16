rule TTP_XOR_MULT_DOSStub_b90d {
  strings:
    $key_b90d = { ed 65 [2] 99 7d [2] de 7f [2] 99 6e [2] d7 62 [2] db 68 [2] cc 63 [2] d7 2d [2] ea }

  condition:
    any of them
}