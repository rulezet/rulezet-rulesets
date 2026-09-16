rule TTP_XOR_MULT_DOSStub_fb66 {
  strings:
    $key_fb66 = { af 0e [2] db 16 [2] 9c 14 [2] db 05 [2] 95 09 [2] 99 03 [2] 8e 08 [2] 95 46 [2] a8 }

  condition:
    any of them
}