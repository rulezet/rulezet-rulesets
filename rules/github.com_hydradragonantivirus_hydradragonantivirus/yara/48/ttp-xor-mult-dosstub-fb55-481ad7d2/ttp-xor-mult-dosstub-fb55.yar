rule TTP_XOR_MULT_DOSStub_fb55 {
  strings:
    $key_fb55 = { af 3d [2] db 25 [2] 9c 27 [2] db 36 [2] 95 3a [2] 99 30 [2] 8e 3b [2] 95 75 [2] a8 }

  condition:
    any of them
}