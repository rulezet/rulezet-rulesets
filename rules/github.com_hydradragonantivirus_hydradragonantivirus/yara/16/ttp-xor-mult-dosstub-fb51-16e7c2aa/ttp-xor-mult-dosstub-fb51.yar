rule TTP_XOR_MULT_DOSStub_fb51 {
  strings:
    $key_fb51 = { af 39 [2] db 21 [2] 9c 23 [2] db 32 [2] 95 3e [2] 99 34 [2] 8e 3f [2] 95 71 [2] a8 }

  condition:
    any of them
}