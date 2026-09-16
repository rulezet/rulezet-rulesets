rule TTP_XOR_MULT_DOSStub_b9ff {
  strings:
    $key_b9ff = { ed 97 [2] 99 8f [2] de 8d [2] 99 9c [2] d7 90 [2] db 9a [2] cc 91 [2] d7 df [2] ea }

  condition:
    any of them
}