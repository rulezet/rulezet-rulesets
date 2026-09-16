rule TTP_XOR_MULT_DOSStub_b96a {
  strings:
    $key_b96a = { ed 02 [2] 99 1a [2] de 18 [2] 99 09 [2] d7 05 [2] db 0f [2] cc 04 [2] d7 4a [2] ea }

  condition:
    any of them
}