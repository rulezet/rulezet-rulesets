rule TTP_XOR_MULT_DOSStub_fb2d {
  strings:
    $key_fb2d = { af 45 [2] db 5d [2] 9c 5f [2] db 4e [2] 95 42 [2] 99 48 [2] 8e 43 [2] 95 0d [2] a8 }

  condition:
    any of them
}