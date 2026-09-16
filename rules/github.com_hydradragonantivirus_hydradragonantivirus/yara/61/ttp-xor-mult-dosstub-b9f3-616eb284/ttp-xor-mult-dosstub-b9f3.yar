rule TTP_XOR_MULT_DOSStub_b9f3 {
  strings:
    $key_b9f3 = { ed 9b [2] 99 83 [2] de 81 [2] 99 90 [2] d7 9c [2] db 96 [2] cc 9d [2] d7 d3 [2] ea }

  condition:
    any of them
}