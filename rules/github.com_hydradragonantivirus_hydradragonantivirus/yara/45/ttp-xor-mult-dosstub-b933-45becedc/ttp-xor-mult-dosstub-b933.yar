rule TTP_XOR_MULT_DOSStub_b933 {
  strings:
    $key_b933 = { ed 5b [2] 99 43 [2] de 41 [2] 99 50 [2] d7 5c [2] db 56 [2] cc 5d [2] d7 13 [2] ea }

  condition:
    any of them
}