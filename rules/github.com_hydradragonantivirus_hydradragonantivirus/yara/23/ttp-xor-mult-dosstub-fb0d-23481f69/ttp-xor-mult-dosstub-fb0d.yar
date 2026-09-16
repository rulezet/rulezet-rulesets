rule TTP_XOR_MULT_DOSStub_fb0d {
  strings:
    $key_fb0d = { af 65 [2] db 7d [2] 9c 7f [2] db 6e [2] 95 62 [2] 99 68 [2] 8e 63 [2] 95 2d [2] a8 }

  condition:
    any of them
}