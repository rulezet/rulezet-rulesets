rule TTP_XOR_MULT_DOSStub_b973 {
  strings:
    $key_b973 = { ed 1b [2] 99 03 [2] de 01 [2] 99 10 [2] d7 1c [2] db 16 [2] cc 1d [2] d7 53 [2] ea }

  condition:
    any of them
}