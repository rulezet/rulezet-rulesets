rule TTP_XOR_MULT_DOSStub_fb16 {
  strings:
    $key_fb16 = { af 7e [2] db 66 [2] 9c 64 [2] db 75 [2] 95 79 [2] 99 73 [2] 8e 78 [2] 95 36 [2] a8 }

  condition:
    any of them
}