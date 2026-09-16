rule TTP_XOR_MULT_DOSStub_fbfc {
  strings:
    $key_fbfc = { af 94 [2] db 8c [2] 9c 8e [2] db 9f [2] 95 93 [2] 99 99 [2] 8e 92 [2] 95 dc [2] a8 }

  condition:
    any of them
}