rule TTP_XOR_MULT_DOSStub_fbfe {
  strings:
    $key_fbfe = { af 96 [2] db 8e [2] 9c 8c [2] db 9d [2] 95 91 [2] 99 9b [2] 8e 90 [2] 95 de [2] a8 }

  condition:
    any of them
}