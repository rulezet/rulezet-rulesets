rule TTP_XOR_MULT_DOSStub_b96f {
  strings:
    $key_b96f = { ed 07 [2] 99 1f [2] de 1d [2] 99 0c [2] d7 00 [2] db 0a [2] cc 01 [2] d7 4f [2] ea }

  condition:
    any of them
}