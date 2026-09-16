rule TTP_XOR_MULT_DOSStub_b96b {
  strings:
    $key_b96b = { ed 03 [2] 99 1b [2] de 19 [2] 99 08 [2] d7 04 [2] db 0e [2] cc 05 [2] d7 4b [2] ea }

  condition:
    any of them
}