rule TTP_XOR_MULT_DOSStub_fb50 {
  strings:
    $key_fb50 = { af 38 [2] db 20 [2] 9c 22 [2] db 33 [2] 95 3f [2] 99 35 [2] 8e 3e [2] 95 70 [2] a8 }

  condition:
    any of them
}