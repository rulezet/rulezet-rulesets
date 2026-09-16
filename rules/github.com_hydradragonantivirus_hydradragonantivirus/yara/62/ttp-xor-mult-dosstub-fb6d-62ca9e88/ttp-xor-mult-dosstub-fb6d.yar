rule TTP_XOR_MULT_DOSStub_fb6d {
  strings:
    $key_fb6d = { af 05 [2] db 1d [2] 9c 1f [2] db 0e [2] 95 02 [2] 99 08 [2] 8e 03 [2] 95 4d [2] a8 }

  condition:
    any of them
}