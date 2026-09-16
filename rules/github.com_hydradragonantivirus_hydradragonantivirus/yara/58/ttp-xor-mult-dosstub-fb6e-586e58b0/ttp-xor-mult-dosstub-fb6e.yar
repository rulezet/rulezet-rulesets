rule TTP_XOR_MULT_DOSStub_fb6e {
  strings:
    $key_fb6e = { af 06 [2] db 1e [2] 9c 1c [2] db 0d [2] 95 01 [2] 99 0b [2] 8e 00 [2] 95 4e [2] a8 }

  condition:
    any of them
}