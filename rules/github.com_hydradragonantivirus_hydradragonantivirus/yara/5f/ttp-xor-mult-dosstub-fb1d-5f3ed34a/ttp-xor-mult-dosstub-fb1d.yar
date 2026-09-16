rule TTP_XOR_MULT_DOSStub_fb1d {
  strings:
    $key_fb1d = { af 75 [2] db 6d [2] 9c 6f [2] db 7e [2] 95 72 [2] 99 78 [2] 8e 73 [2] 95 3d [2] a8 }

  condition:
    any of them
}