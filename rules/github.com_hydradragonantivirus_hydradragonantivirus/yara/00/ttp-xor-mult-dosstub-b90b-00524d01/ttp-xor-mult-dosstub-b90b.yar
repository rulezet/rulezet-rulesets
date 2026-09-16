rule TTP_XOR_MULT_DOSStub_b90b {
  strings:
    $key_b90b = { ed 63 [2] 99 7b [2] de 79 [2] 99 68 [2] d7 64 [2] db 6e [2] cc 65 [2] d7 2b [2] ea }

  condition:
    any of them
}