rule TTP_XOR_MULT_DOSStub_b9eb {
  strings:
    $key_b9eb = { ed 83 [2] 99 9b [2] de 99 [2] 99 88 [2] d7 84 [2] db 8e [2] cc 85 [2] d7 cb [2] ea }

  condition:
    any of them
}