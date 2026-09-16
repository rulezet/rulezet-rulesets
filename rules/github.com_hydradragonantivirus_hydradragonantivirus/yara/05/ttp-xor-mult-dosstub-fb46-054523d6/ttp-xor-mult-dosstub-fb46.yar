rule TTP_XOR_MULT_DOSStub_fb46 {
  strings:
    $key_fb46 = { af 2e [2] db 36 [2] 9c 34 [2] db 25 [2] 95 29 [2] 99 23 [2] 8e 28 [2] 95 66 [2] a8 }

  condition:
    any of them
}